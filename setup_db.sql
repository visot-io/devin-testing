-- Connect to aws_security database
\c aws_security;

-- Create table if it doesn't exist
CREATE TABLE IF NOT EXISTS aws_project_status (
    id SERIAL PRIMARY KEY,
    description TEXT,
    resource TEXT,
    status VARCHAR(50),
    check_type VARCHAR(100)
);

-- Add check_type column if it doesn't exist
DO $$ 
BEGIN 
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name='aws_project_status' 
        AND column_name='check_type'
    ) THEN
        ALTER TABLE aws_project_status ADD COLUMN check_type VARCHAR(100);
    END IF;
END $$;
