"""One ordinary five-table SQLAlchemy application on native and Forkget URLs."""

from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import BigInteger, Boolean, Date, DateTime, ForeignKey, Integer, Numeric, String
from sqlalchemy import MetaData, Table, func, inspect, select
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship
from sqlalchemy.orm.exc import StaleDataError


MOMENT = datetime(2024, 2, 29, 12, 34, 56, 123456)
DAY = date(2024, 2, 29)
TIMESTAMP = DateTime().with_variant(DATETIME(fsp=6), "mysql")


class Base(DeclarativeBase):
    pass


class Customer(Base):
    __tablename__ = "customers"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    orders: Mapped[list["Order"]] = relationship(back_populates="customer")
    payments: Mapped[list["Payment"]] = relationship(back_populates="customer")


class Product(Base):
    __tablename__ = "products"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    sku: Mapped[str] = mapped_column(String(64), unique=True)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    lines: Mapped[list["Line"]] = relationship(back_populates="product")


class Order(Base):
    __tablename__ = "orders"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"))
    reference: Mapped[str] = mapped_column(String(64), unique=True)
    title: Mapped[str] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    booked_on: Mapped[date] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.current_timestamp(6))
    customer: Mapped[Customer] = relationship(back_populates="orders")
    lines: Mapped[list["Line"]] = relationship(back_populates="order")
    payments: Mapped[list["Payment"]] = relationship(back_populates="order")
    __mapper_args__ = {"version_id_col": version}


class Line(Base):
    __tablename__ = "lines"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id"))
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"))
    reference: Mapped[str] = mapped_column(String(64), unique=True)
    quantity: Mapped[int] = mapped_column(Integer)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    occurred_at: Mapped[datetime] = mapped_column(TIMESTAMP)
    order: Mapped[Order] = relationship(back_populates="lines")
    product: Mapped[Product] = relationship(back_populates="lines")


class Payment(Base):
    __tablename__ = "payments"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id"))
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"))
    reference: Mapped[str] = mapped_column(String(64), unique=True)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    settled: Mapped[bool] = mapped_column(Boolean, default=False)
    paid_on: Mapped[date] = mapped_column(Date)
    recorded_at: Mapped[datetime] = mapped_column(TIMESTAMP)
    order: Mapped[Order] = relationship(back_populates="payments")
    customer: Mapped[Customer] = relationship(back_populates="payments")


MODELS = (Customer, Product, Order, Line, Payment)
BUSINESS_KEYS = {"customers": "code", "products": "sku", "orders": "reference",
                 "lines": "reference", "payments": "reference"}
SEED_KEYS = {"customers": "seed-customer", "products": "seed-product", "orders": "seed-order",
             "lines": "seed-line", "payments": "seed-payment"}
SEED_ORIGINAL_TITLE = "seed-original"
SEED_UPDATED_TITLE = "seed-updated"
SEED_UNIT_PRICE = Decimal("7.25")
SEED_QUANTITY = 2
SEED_AMOUNT = SEED_UNIT_PRICE * SEED_QUANTITY
SEED_COUNTS = {name: 1 for name in BUSINESS_KEYS}
APP_COUNTS = {"customers": 1, "products": 2, "orders": 1, "lines": 1000, "payments": 1}
FINAL_COUNTS = {name: SEED_COUNTS[name] + APP_COUNTS[name] for name in BUSINESS_KEYS}


def reflect(engine):
    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == set(Base.metadata.tables)
    assert not inspector.has_table("not_registered")
    schema = {}
    for name, table in Base.metadata.tables.items():
        assert inspector.has_table(name)
        columns = inspector.get_columns(name)
        assert [column["name"] for column in columns] == list(table.columns.keys())
        assert all(column["nullable"] == table.columns[column["name"]].nullable for column in columns)
        assert columns[0]["autoincrement"] is True
        assert inspector.get_pk_constraint(name)["constrained_columns"] == ["id"]
        expected = {(tuple(key.column_keys), key.referred_table.name,
                     tuple(element.column.name for element in key.elements))
                    for key in table.foreign_key_constraints}
        actual = {(tuple(key["constrained_columns"]), key["referred_table"], tuple(key["referred_columns"]))
                  for key in inspector.get_foreign_keys(name)}
        assert actual == expected, (name, "foreign keys", actual, expected)
        unique = {tuple(key["column_names"]) for key in inspector.get_unique_constraints(name)}
        assert (BUSINESS_KEYS[name],) in unique
        for column in columns:
            declared = table.columns[column["name"]].type
            if isinstance(declared, Numeric):
                assert column["type"].precision == 12 and column["type"].scale == 2
            if isinstance(declared, DateTime):
                precision = getattr(column["type"], "fsp", getattr(column["type"], "precision", None))
                assert precision in (None, 6), (name, column["name"], precision)
        inspector.get_indexes(name)
        inspector.get_check_constraints(name)
        Table(name, MetaData(), autoload_with=engine)
        schema[name] = [{"name": column["name"], "native_type": str(column["type"]),
                         "nullable": column["nullable"], "generated": column.get("autoincrement") is True}
                        for column in columns]
    return schema


def read_state(engine):
    """Read every typed row with the ordinary ORM, before or after application work."""
    state = {}
    with Session(engine) as session:
        for model in MODELS:
            rows = session.scalars(select(model).order_by(model.id)).all()
            state[model.__tablename__] = [
                {column.name: getattr(row, column.name) for column in model.__table__.columns}
                for row in rows
            ]
    return state


def seed_source(engine):
    """Populate all five source tables using normal native generated keys."""
    assert all(not rows for rows in read_state(engine).values()), "seed source must start empty"
    with Session(engine) as session:
        customer = Customer(code=SEED_KEYS["customers"], active=True)
        product = Product(sku=SEED_KEYS["products"], unit_price=SEED_UNIT_PRICE, active=False)
        order = Order(customer=customer, reference=SEED_KEYS["orders"], title=SEED_ORIGINAL_TITLE,
                      booked_on=DAY, created_at=MOMENT)
        line = Line(order=order, product=product, reference=SEED_KEYS["lines"],
                    quantity=SEED_QUANTITY, amount=SEED_AMOUNT, active=False, occurred_at=MOMENT)
        payment = Payment(order=order, customer=customer, reference=SEED_KEYS["payments"],
                          amount=SEED_AMOUNT, settled=True, paid_on=DAY, recorded_at=MOMENT)
        session.add_all([customer, product, order, line, payment])
        session.flush()
        assert all(type(row.id) is int and 0 < row.id < (1 << 62)
                   for row in (customer, product, order, line, payment))
        assert order.version == 1
        session.commit()
    state = assert_seed(engine)
    assert {name: len(rows) for name, rows in state.items()} == SEED_COUNTS
    return state


def assert_seed(engine, updated=False):
    """Assert the imported seed chain without assuming the app workflow has run."""
    with Session(engine) as session:
        rows = {
            model.__tablename__: session.scalars(
                select(model).where(getattr(model, BUSINESS_KEYS[model.__tablename__])
                                    == SEED_KEYS[model.__tablename__])
            ).one()
            for model in MODELS
        }
        customer, product, order, line, payment = (rows[model.__tablename__] for model in MODELS)
        assert all(type(row.id) is int and 0 < row.id < (1 << 62) for row in rows.values())
        assert customer.code == SEED_KEYS["customers"] and customer.active is True
        assert product.sku == SEED_KEYS["products"] and product.active is False
        assert isinstance(product.unit_price, Decimal) and product.unit_price == SEED_UNIT_PRICE
        assert order.reference == SEED_KEYS["orders"]
        assert order.title == (SEED_UPDATED_TITLE if updated else SEED_ORIGINAL_TITLE)
        assert order.version == (2 if updated else 1)
        assert type(order.booked_on) is date and order.booked_on == DAY
        assert isinstance(order.created_at, datetime) and order.created_at == MOMENT
        assert order.customer is customer and customer.orders == [order]
        assert line.reference == SEED_KEYS["lines"] and line.quantity == SEED_QUANTITY
        assert isinstance(line.amount, Decimal) and line.amount == SEED_AMOUNT and line.active is False
        assert isinstance(line.occurred_at, datetime) and line.occurred_at == MOMENT
        assert line.order is order and line.product is product
        assert order.lines == [line] and product.lines == [line]
        assert payment.reference == SEED_KEYS["payments"] and payment.settled is True
        assert isinstance(payment.amount, Decimal) and payment.amount == SEED_AMOUNT
        assert type(payment.paid_on) is date and payment.paid_on == DAY
        assert isinstance(payment.recorded_at, datetime) and payment.recorded_at == MOMENT
        assert payment.order is order and payment.customer is customer
        assert order.payments == [payment] and customer.payments == [payment]
    state = read_state(engine)
    for name, values in state.items():
        seeds = [row for row in values if row[BUSINESS_KEYS[name]].startswith("seed-")]
        assert len(seeds) == 1 and seeds[0][BUSINESS_KEYS[name]] == SEED_KEYS[name]
    return state


def line_amount(number):
    return (Decimal("12.34") if number % 2 == 0 else Decimal("56.78")) * (number % 3 + 1)


def exercise(engine, prefix="app"):
    """Use normal flush, RETURNING, bulk paging, lazy loads and version checks."""
    reflect(engine)
    assert_seed(engine)
    with Session(engine) as session:
        # This normal ORM UPDATE belongs to the same first transaction as the
        # later 1001-line flush. A budget refusal must roll it back with new rows.
        seed_order = session.scalars(select(Order).where(Order.reference == SEED_KEYS["orders"])).one()
        assert seed_order.title == SEED_ORIGINAL_TITLE and seed_order.version == 1
        seed_order.title = SEED_UPDATED_TITLE
        session.flush()
        assert seed_order.title == SEED_UPDATED_TITLE and seed_order.version == 2
        customer = Customer(code=prefix + "-customer")
        products = [Product(sku=prefix + "-basic", unit_price=Decimal("12.34")),
                    Product(sku=prefix + "-premium", unit_price=Decimal("56.78"))]
        order = Order(customer=customer, reference=prefix + "-order", title=prefix + "-order", booked_on=DAY)
        payment = Payment(order=order, customer=customer, reference=prefix + "-payment",
                          amount=sum((line_amount(number) for number in range(1001)), Decimal("0.00")),
                          paid_on=DAY, recorded_at=MOMENT)
        session.add_all([order, payment, *products])
        session.flush()
        assert all(row.id > 0 for row in (customer, *products, order, payment))
        assert order.version == 1 and isinstance(order.created_at, datetime)
        # Preserve server-default retrieval above, then make the business event
        # time deterministic for exact native/proxy/replay state comparison.
        order.created_at = MOMENT
        draft = Line(order=order, product=products[0], reference=prefix + "-draft", quantity=1,
                     amount=Decimal("12.34"), active=True, occurred_at=MOMENT)
        session.add(draft)
        session.flush()
        session.delete(draft)
        session.flush()
        assert order.version == 2
        lines = [Line(order=order, product=products[number % 2], reference=f"{prefix}-{number:04d}",
                      quantity=number % 3 + 1, amount=line_amount(number), active=number % 2 == 0,
                      occurred_at=MOMENT) for number in range(1001)]
        session.add_all(lines)
        session.flush()
        assert len({line.id for line in lines}) == 1001
        assert all(line.id > 0 and line.reference == f"{prefix}-{number:04d}"
                   for number, line in enumerate(lines))
        order_id = order.id
        session.commit()

    with Session(engine) as left, Session(engine) as right:
        first = left.get(Order, order_id)
        stale = right.get(Order, order_id)
        first.title = prefix + "-updated"
        left.commit()
        stale.title = prefix + "-stale"
        try:
            right.commit()
            raise AssertionError("the optimistic version conflict was lost")
        except StaleDataError:
            right.rollback()

    with Session(engine) as session:
        order = session.get(Order, order_id)
        assert order.version == 3 and order.title == prefix + "-updated"
        assert len(order.lines) == 1001 and order.customer.code == prefix + "-customer"
        assert len(order.payments) == 1 and order.payments[0].customer is order.customer
        active = session.scalars(select(Line).where(Line.active.is_(True)).order_by(Line.reference).limit(10)).all()
        assert len(active) == 10 and all(line.active is True for line in active)
        assert active[0].occurred_at.microsecond == 123456 and active[0].amount == Decimal("12.34")
        victim = session.scalar(select(Line).where(Line.reference == prefix + "-1000"))
        session.delete(victim)
        order.payments[0].amount -= line_amount(1000)
        order.payments[0].settled = True
        premium = session.scalars(select(Product).where(Product.sku == prefix + "-premium")).one()
        premium.active = False
        session.commit()
        assert session.scalar(select(func.count()).select_from(Line)) == FINAL_COUNTS["lines"]
    state = assert_seed(engine, updated=True)
    counts = {name: len(rows) for name, rows in state.items()}
    assert counts == FINAL_COUNTS
    return {**counts, "app_counts": dict(APP_COUNTS), "seed_counts": dict(SEED_COUNTS),
            "version": 3, "date": DAY.isoformat(), "microseconds": MOMENT.microsecond,
            "optimistic_conflict": True, "bulk_input": 1001, "draft_replaced": True,
            "server_default_returned": True, "seed_order_updated": True, "seed_order_version": 2}


def observe(engine, prefix="app"):
    """Assert all five committed tables and retain exact IDs and typed values."""
    reflect(engine)
    with Session(engine) as session:
        order = session.scalar(select(Order).where(Order.reference == prefix + "-order"))
        assert order is not None and order.version == 3 and order.title == prefix + "-updated"
        assert order.booked_on == DAY and order.created_at == MOMENT
        assert order.customer.code == prefix + "-customer" and order.customer.active is True
        products = {product.sku: product for product in session.scalars(select(Product)).all()}
        assert set(products) == {SEED_KEYS["products"], prefix + "-basic", prefix + "-premium"}
        assert products[prefix + "-basic"].unit_price == Decimal("12.34")
        assert products[prefix + "-premium"].unit_price == Decimal("56.78")
        assert products[prefix + "-basic"].active is True and products[prefix + "-premium"].active is False
        assert len(order.lines) == 1000
        assert {line.reference for line in order.lines} == {f"{prefix}-{number:04d}" for number in range(1000)}
        for line in order.lines:
            number = int(line.reference.rsplit("-", 1)[1])
            assert line.active is (number % 2 == 0)
            assert line.quantity == number % 3 + 1 and line.amount == line_amount(number)
            assert line.occurred_at == MOMENT
            assert line.product.sku == prefix + ("-basic" if number % 2 == 0 else "-premium")
        assert len(order.payments) == 1
        payment = order.payments[0]
        assert payment.reference == prefix + "-payment" and payment.customer is order.customer
        assert payment.settled is True and payment.paid_on == DAY and payment.recorded_at == MOMENT
        assert payment.amount == sum((line.amount for line in order.lines), Decimal("0.00"))
    state = assert_seed(engine, updated=True)
    assert {name: len(rows) for name, rows in state.items()} == FINAL_COUNTS
    return state


def canonical(state):
    """Compare independent native sequences by stable business keys and real FKs."""
    keys = {name: {row["id"]: row[BUSINESS_KEYS[name]] for row in rows} for name, rows in state.items()}
    result = {}
    for name, rows in state.items():
        table = Base.metadata.tables[name]
        normalized = []
        for row in rows:
            values = dict(row)
            values["id"] = keys[name][row["id"]]
            for key in table.foreign_keys:
                values[key.parent.name] = keys[key.column.table.name][row[key.parent.name]]
            normalized.append(values)
        result[name] = sorted(normalized, key=lambda row: row["id"])
    return result


def constraint_checks(engine, state, prefix="app"):
    """Native uniqueness and all five foreign keys must reject invalid ORM writes."""
    unique_failures = foreign_key_failures = 0
    for model in MODELS:
        row = state[model.__tablename__][0]
        with Session(engine) as session:
            session.add(model(**{key: value for key, value in row.items() if key != "id"}))
            try:
                session.flush()
                raise AssertionError("duplicate business key was accepted: " + model.__tablename__)
            except IntegrityError:
                session.rollback()
                unique_failures += 1
    for model in MODELS:
        table = model.__table__
        for foreign_key in sorted(table.foreign_keys, key=lambda key: key.parent.name):
            row = {key: value for key, value in state[model.__tablename__][0].items() if key != "id"}
            row[BUSINESS_KEYS[model.__tablename__]] = prefix + "-orphan-" + foreign_key.parent.name
            row[foreign_key.parent.name] = max(item["id"] for item in state[foreign_key.column.table.name]) + 1_000_000
            with Session(engine) as session:
                session.add(model(**row))
                try:
                    session.flush()
                    raise AssertionError("orphan foreign key was accepted: " + str(foreign_key))
                except IntegrityError:
                    session.rollback()
                    foreign_key_failures += 1
    assert unique_failures == 5 and foreign_key_failures == 5
    assert observe(engine, prefix) == state
    return {"unique_refusals": unique_failures, "foreign_key_refusals": foreign_key_failures}


def next_allocations(engine, state):
    """Every replayed generated-key table must accept its next ordinary ORM key."""
    with Session(engine) as session:
        customer = Customer(code="after-replay-customer")
        product = Product(sku="after-replay-product", unit_price=Decimal("12.34"))
        order = Order(customer=customer, reference="after-replay-order", title="after-replay", booked_on=DAY)
        line = Line(order=order, product=product, reference="after-replay-line", quantity=1,
                    amount=Decimal("12.34"), active=True, occurred_at=MOMENT)
        payment = Payment(order=order, customer=customer, reference="after-replay-payment",
                          amount=Decimal("12.34"), paid_on=DAY, recorded_at=MOMENT)
        session.add_all([customer, product, order, line, payment])
        session.flush()
        allocated = {}
        for row in (customer, product, order, line, payment):
            name = row.__tablename__
            maximum = max(item["id"] for item in state[name])
            assert row.id > maximum, (name, row.id, maximum)
            allocated[name] = {"max_replayed_id": maximum, "next_generated_id": row.id}
        assert isinstance(order.created_at, datetime)
        session.rollback()
    assert observe(engine) == state
    return allocated


def typed_json(value):
    """Keep actual Python types and exact values in JSON evidence."""
    if isinstance(value, dict):
        return {key: typed_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [typed_json(item) for item in value]
    if isinstance(value, Decimal):
        return {"type": "Decimal", "value": str(value)}
    if isinstance(value, datetime):
        return {"type": "datetime", "value": value.isoformat(timespec="microseconds")}
    if isinstance(value, date):
        return {"type": "date", "value": value.isoformat()}
    return value
