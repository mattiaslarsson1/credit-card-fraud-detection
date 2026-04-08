SELECT 
    table_name,
    column_name, 
    data_type, 
    is_nullable, 
    column_default
FROM information_schema.columns
WHERE table_name IN (
    'bank',
    'customer',
    'account',
    'credit_card',
    'merchant',
    'device',
    'transaction',
    'fraud_alert',
    'fraud_report',
    'authorized_user'
)
ORDER BY table_name, ordinal_position;