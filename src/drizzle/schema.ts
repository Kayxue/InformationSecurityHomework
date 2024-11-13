import {
	pgTable,
	text,
	varchar,
	timestamp,
	boolean,
} from "drizzle-orm/pg-core";
import { nanoid } from "nanoid";

export const users = pgTable("users", {
	id: varchar("id", { length: 21 })
		.$defaultFn(() => nanoid())
		.primaryKey()
		.notNull(),
	username: text("username").notNull().unique(),
	password: text("password").notNull(),
	passwordOld1: text("passwordOld1").default("").notNull(),
	passwordOld2: text("passwordOld2").default("").notNull(),
	name: text("name").notNull(),
});

export const logs = pgTable("logs", {
	id: varchar("id", { length: 21 })
		.$defaultFn(() => nanoid())
		.primaryKey()
		.notNull(),
	username: text("username").notNull(),
	ip: text("ip").notNull(),
	timestamp: timestamp("timestamp", { mode: "date" }).notNull(),
	result: boolean("result").notNull(),
	locked: boolean("locked").notNull(),
});
