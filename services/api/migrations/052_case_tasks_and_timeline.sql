-- 052: case_tasks and case_timeline
--
-- These two ORM tables were only ever created by SQLAlchemy create_all, which
-- runs in ENVIRONMENT=development only. A production database built from the
-- SQL migrations lacked them, so case tasks and the case timeline failed there.
-- DDL generated from the ORM models (app.models), guarded with IF NOT EXISTS so
-- it is a no-op on databases where create_all already made them.

CREATE TABLE IF NOT EXISTS case_tasks (
	id UUID NOT NULL, 
	case_id UUID NOT NULL, 
	tenant_id UUID NOT NULL, 
	title VARCHAR(500) NOT NULL, 
	description TEXT, 
	status VARCHAR(20) NOT NULL, 
	assigned_to_id UUID, 
	due_date TIMESTAMP WITH TIME ZONE, 
	completed_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(case_id) REFERENCES cases (id)
);

CREATE INDEX IF NOT EXISTS ix_case_tasks_case_id ON case_tasks (case_id);

CREATE INDEX IF NOT EXISTS ix_case_tasks_tenant_id ON case_tasks (tenant_id);

CREATE TABLE IF NOT EXISTS case_timeline (
	id UUID NOT NULL, 
	case_id UUID NOT NULL, 
	tenant_id UUID NOT NULL, 
	event_type VARCHAR(50) NOT NULL, 
	content TEXT NOT NULL, 
	metadata JSONB NOT NULL, 
	user_id UUID, 
	is_automated BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(case_id) REFERENCES cases (id)
);

CREATE INDEX IF NOT EXISTS ix_case_timeline_case_id ON case_timeline (case_id);

CREATE INDEX IF NOT EXISTS ix_case_timeline_created_at ON case_timeline (created_at);
