use sqlparser::ast::{
    BinaryOperator, CastKind, CharacterLength, DataType, Expr, Function, FunctionArg,
    FunctionArgExpr, FunctionArguments, ObjectNamePart, Query, UnaryOperator, Value, WindowType,
};

use crate::Dialect;

use super::{CompileError, Compiler, Result, scope::Context};

const MAX_EXPRESSION_DEPTH: usize = 48;

impl Compiler<'_> {
    pub(super) fn exprs(&mut self, exprs: &[Expr], ctx: Context<'_>, depth: usize) -> Result<()> {
        for expr in exprs {
            self.expr(expr, ctx, depth)?;
        }
        Ok(())
    }

    pub(super) fn expr(&mut self, expr: &Expr, ctx: Context<'_>, depth: usize) -> Result<()> {
        if depth >= MAX_EXPRESSION_DEPTH {
            return Err(CompileError::Syntax);
        }
        let child = depth + 1;
        match expr {
            Expr::Identifier(ident) => self.column(std::slice::from_ref(ident), ctx).map(drop),
            Expr::CompoundIdentifier(parts) => self.column(parts, ctx).map(drop),
            Expr::Value(value) => check_value(self.dialect, &value.value),
            Expr::Nested(expr)
            | Expr::IsFalse(expr)
            | Expr::IsNotFalse(expr)
            | Expr::IsTrue(expr)
            | Expr::IsNotTrue(expr)
            | Expr::IsNull(expr)
            | Expr::IsNotNull(expr)
            | Expr::IsUnknown(expr)
            | Expr::IsNotUnknown(expr) => self.expr(expr, ctx, child),
            Expr::UnaryOp {
                op: UnaryOperator::Plus | UnaryOperator::Minus | UnaryOperator::Not,
                expr,
            } => self.expr(expr, ctx, child),
            Expr::BinaryOp { left, op, right } if allows_operator(self.dialect, op) => {
                self.pair(left, right, ctx, child)
            }
            Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right)
                if self.dialect == Dialect::PostgreSql =>
            {
                self.pair(left, right, ctx, child)
            }
            Expr::InList {
                expr,
                list,
                negated: _,
            } if !list.is_empty() => {
                self.expr(expr, ctx, child)?;
                self.exprs(list, ctx, child)
            }
            Expr::Between {
                expr,
                negated: _,
                low,
                high,
            } => {
                self.expr(expr, ctx, child)?;
                self.pair(low, high, ctx, child)
            }
            Expr::ILike {
                negated: _,
                any: false,
                expr,
                pattern,
                escape_char,
            } if self.dialect == Dialect::PostgreSql => {
                self.like(expr, pattern, escape_char.as_deref(), ctx, child)
            }
            Expr::Like {
                negated: _,
                any: false,
                expr,
                pattern,
                escape_char,
            } => self.like(expr, pattern, escape_char.as_deref(), ctx, child),
            Expr::Cast {
                kind,
                expr,
                data_type,
                format: None,
            } if allows_cast(self.dialect, kind, data_type) => self.expr(expr, ctx, child),
            Expr::Function(function) => self.function(function, ctx, child),
            Expr::Case {
                operand,
                conditions,
                else_result,
                case_token: _,
                end_token: _,
            } => {
                if let Some(operand) = operand {
                    self.expr(operand, ctx, child)?;
                }
                for when in conditions {
                    self.pair(&when.condition, &when.result, ctx, child)?;
                }
                if let Some(result) = else_result {
                    self.expr(result, ctx, child)?;
                }
                Ok(())
            }
            Expr::InSubquery {
                expr,
                subquery,
                negated: _,
            } => {
                self.expr(expr, ctx, child)?;
                self.subquery(subquery, ctx, true)
            }
            Expr::Exists {
                subquery,
                negated: _,
            } => self.subquery(subquery, ctx, false),
            Expr::Subquery(subquery) => self.subquery(subquery, ctx, true),
            _ => Err(CompileError::Unsupported),
        }
    }

    fn pair(&mut self, first: &Expr, second: &Expr, ctx: Context<'_>, depth: usize) -> Result<()> {
        self.expr(first, ctx, depth)?;
        self.expr(second, ctx, depth)
    }

    fn like(
        &mut self,
        expr: &Expr,
        pattern: &Expr,
        escape: Option<&Expr>,
        ctx: Context<'_>,
        depth: usize,
    ) -> Result<()> {
        self.pair(expr, pattern, ctx, depth)?;
        if let Some(escape) = escape {
            self.expr(escape, ctx, depth)?;
        }
        Ok(())
    }

    fn subquery(&mut self, query: &Query, ctx: Context<'_>, scalar: bool) -> Result<()> {
        let mut outer = ctx.outer.to_vec();
        outer.push(ctx.scope.clone());
        let result = self.query(query, ctx.ctes, &outer)?;
        if scalar && result.columns.len() != 1 {
            return Err(CompileError::Unsupported);
        }
        Ok(())
    }

    fn function(&mut self, function: &Function, ctx: Context<'_>, depth: usize) -> Result<()> {
        let name = function_name(function)?;
        if function.uses_odbc_syntax
            || !matches!(function.parameters, FunctionArguments::None)
            || !function.within_group.is_empty()
            || function.filter.is_some()
            || function.null_treatment.is_some()
        {
            return Err(CompileError::Function);
        }
        let FunctionArguments::List(args) = &function.args else {
            return Err(CompileError::Function);
        };
        if !args.clauses.is_empty()
            || !allows_arity(&name, args.args.len())
            || (args.duplicate_treatment.is_some() && !is_aggregate(&name))
        {
            return Err(CompileError::Function);
        }
        for arg in &args.args {
            match arg {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => self.expr(expr, ctx, depth)?,
                FunctionArg::Unnamed(FunctionArgExpr::Wildcard)
                    if name == "COUNT" && args.duplicate_treatment.is_none() => {}
                _ => return Err(CompileError::Function),
            }
        }
        match (&*name, &function.over) {
            ("ROW_NUMBER", Some(WindowType::WindowSpec(window)))
                if window.window_name.is_none() && window.window_frame.is_none() =>
            {
                self.exprs(&window.partition_by, ctx, depth)?;
                self.order_by(&window.order_by, ctx)
            }
            ("ROW_NUMBER", _) | (_, Some(_)) => Err(CompileError::Function),
            _ => Ok(()),
        }
    }

    pub(super) fn implicit_name(&self, expr: &Expr) -> Option<String> {
        match self.dialect {
            Dialect::PostgreSql => pg_implicit_name(expr),
            Dialect::MySql => None,
        }
    }

    pub(super) fn limit_value(&mut self, expr: &Expr, ctx: Context<'_>) -> Result<()> {
        if let Expr::Cast {
            kind,
            expr,
            data_type,
            format: None,
        } = expr
            && self.dialect == Dialect::PostgreSql
            && allows_cast(self.dialect, kind, data_type)
            && matches!(
                data_type,
                DataType::Int(None)
                    | DataType::Integer(None)
                    | DataType::BigInt(None)
                    | DataType::Int4(None)
                    | DataType::Int8(None)
            )
        {
            return self.limit_value(expr, ctx);
        }
        let Expr::Value(value) = expr else {
            return Err(CompileError::Unsupported);
        };
        match &value.value {
            Value::Number(number, false) if number.bytes().all(|byte| byte.is_ascii_digit()) => {
                self.expr(expr, ctx, 0)
            }
            Value::Placeholder(_) => self.expr(expr, ctx, 0),
            _ => Err(CompileError::Unsupported),
        }
    }
}

pub(super) fn check_value(dialect: Dialect, value: &Value) -> Result<()> {
    match value {
        Value::Number(_, false)
        | Value::SingleQuotedString(_)
        | Value::Boolean(_)
        | Value::Null
        | Value::Placeholder(_) => Ok(()),
        Value::DoubleQuotedString(_) | Value::HexStringLiteral(_) if dialect == Dialect::MySql => {
            Ok(())
        }
        Value::EscapedStringLiteral(_) | Value::DollarQuotedString(_)
            if dialect == Dialect::PostgreSql =>
        {
            Ok(())
        }
        _ => Err(CompileError::Unsupported),
    }
}

fn allows_operator(dialect: Dialect, op: &BinaryOperator) -> bool {
    matches!(
        op,
        BinaryOperator::Plus
            | BinaryOperator::Minus
            | BinaryOperator::Multiply
            | BinaryOperator::Divide
            | BinaryOperator::Modulo
            | BinaryOperator::Gt
            | BinaryOperator::Lt
            | BinaryOperator::GtEq
            | BinaryOperator::LtEq
            | BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::And
            | BinaryOperator::Or
    ) || match dialect {
        Dialect::MySql => matches!(
            op,
            BinaryOperator::Spaceship | BinaryOperator::MyIntegerDivide
        ),
        Dialect::PostgreSql => matches!(op, BinaryOperator::StringConcat),
    }
}

pub(super) fn allows_cast(dialect: Dialect, kind: &CastKind, data_type: &DataType) -> bool {
    match dialect {
        Dialect::MySql => {
            matches!(kind, CastKind::Cast)
                && match data_type {
                    DataType::Signed
                    | DataType::SignedInteger
                    | DataType::Unsigned
                    | DataType::UnsignedInteger
                    | DataType::Binary(_)
                    | DataType::Decimal(_)
                    | DataType::Dec(_) => true,
                    DataType::Char(length) => allowed_character_length(length.as_ref()),
                    _ => false,
                }
        }
        Dialect::PostgreSql => {
            matches!(kind, CastKind::Cast | CastKind::DoubleColon)
                && match data_type {
                    DataType::Int(None)
                    | DataType::Integer(None)
                    | DataType::SmallInt(None)
                    | DataType::BigInt(None)
                    | DataType::Int2(None)
                    | DataType::Int4(None)
                    | DataType::Int8(None)
                    | DataType::Text
                    | DataType::Bytea
                    | DataType::Bool
                    | DataType::Boolean
                    | DataType::Date
                    | DataType::Timestamp(_, _)
                    | DataType::Decimal(_)
                    | DataType::Dec(_)
                    | DataType::Numeric(_) => true,
                    DataType::Char(length)
                    | DataType::Character(length)
                    | DataType::Varchar(length)
                    | DataType::CharacterVarying(length)
                    | DataType::CharVarying(length) => allowed_character_length(length.as_ref()),
                    _ => false,
                }
        }
    }
}

fn allowed_character_length(length: Option<&CharacterLength>) -> bool {
    matches!(
        length,
        None | Some(CharacterLength::IntegerLength {
            length: _,
            unit: None
        })
    )
}

fn function_name(function: &Function) -> Result<String> {
    let [ObjectNamePart::Identifier(name)] = function.name.0.as_slice() else {
        return Err(CompileError::Function);
    };
    if name.quote_style.is_some() {
        return Err(CompileError::Function);
    }
    Ok(name.value.to_ascii_uppercase())
}

fn is_aggregate(name: &str) -> bool {
    matches!(name, "COUNT" | "SUM" | "MIN" | "MAX" | "AVG")
}

fn allows_arity(name: &str, count: usize) -> bool {
    match name {
        "ROW_NUMBER" => count == 0,
        "COALESCE" => count >= 2,
        "ABS" | "LOWER" | "UPPER" => count == 1,
        aggregate if is_aggregate(aggregate) => count == 1,
        _ => false,
    }
}

fn pg_implicit_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Function(function) => function_name(function)
            .map(|name| name.to_ascii_lowercase())
            .ok(),
        Expr::Case { .. } => Some("case".to_owned()),
        Expr::Exists { .. } => Some("exists".to_owned()),
        Expr::Nested(expr) => pg_implicit_name(expr),
        _ => None,
    }
}
