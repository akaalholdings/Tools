SELECT
    s.name AS linked_server_name,
    s.product,
    s.provider,
    s.data_source,
    s.location,
    s.provider_string,
    s.catalog,
    s.connect_timeout,
    s.query_timeout,
    s.is_data_access_enabled,
    s.is_rpc_out_enabled,
    s.is_remote_login_enabled,
    s.is_collation_compatible,
    s.uses_remote_collation,
    s.collation_name,
    s.lazy_schema_validation,
    s.is_remote_proc_transaction_promotion_enabled,
    s.modify_date
FROM sys.servers AS s
WHERE s.server_id <> 0
ORDER BY s.name;
