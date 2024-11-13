CREATE TABLE IF NOT EXISTS "logs" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"username" text NOT NULL,
	"ip" text NOT NULL,
	"timestamp" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "users" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"username" text NOT NULL,
	"password" text NOT NULL,
	"name" text NOT NULL
);
