import { defineConfig } from "drizzle-kit";
import { link } from "../Config.ts";

export default defineConfig({
	dialect: "postgresql",
	schema: "./schema.ts",
	out: "./migrations",
	dbCredentials: {
		url: link,
	},
});
