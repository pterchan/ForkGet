SELECT d."tenant_id", d."id", d."amount", d."note"
FROM "forkget_delta"."_d_g1_t1" AS d
WHERE d."_fg_branch" = 7 AND d."_fg_op" IN ('I', 'U')
UNION ALL
SELECT b."tenant_id", b."id", b."amount", b."note"
FROM "fg_g1"."orders" AS b
LEFT JOIN "forkget_delta"."_d_g1_t1" AS hidden ON hidden."_fg_branch" = 7 AND hidden."tenant_id" = b."tenant_id" AND hidden."id" = b."id"
WHERE hidden."tenant_id" IS NULL
