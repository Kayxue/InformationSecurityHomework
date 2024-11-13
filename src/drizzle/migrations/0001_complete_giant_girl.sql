ALTER TABLE "logs" ADD COLUMN "result" boolean;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "passwordOld1" text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "passwordOld2" text DEFAULT '' NOT NULL;