import { pgTable, text } from "drizzle-orm/pg-core";
import { nanoid } from "nanoid";

export const users = pgTable("users", {
	id: text("id")
		.$defaultFn(() => nanoid())
		.primaryKey()
		.notNull(),
	username: text("username").notNull(),
	password: text("password").notNull(),
	name: text("name").notNull(),
});

// export const logs=pgTable('logs',{

// })
