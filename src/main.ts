import { Hono } from "hono";
import { getConnInfo } from "hono/deno";
import {
	CookieStore,
	Session,
	sessionMiddleware,
} from "jsr:@jcs224/hono-sessions";
import { drizzle } from "drizzle-orm/node-postgres";
import { link, sessionKey } from "./Config.ts";
import { hash, Variant, verify, Version } from "@felix/argon2";
import * as schema from "./drizzle/schema.ts";
import { zValidator } from "@hono/zod-validator";
import { loginSchema, registerSchema } from "./ZodSchema.ts";
import { eq } from "drizzle-orm";

const db = drizzle(link, { schema });

const app = new Hono<{
	Variables: { session: Session; session_key_rotation: boolean };
}>();

const store = new CookieStore();

app.use(
	"*",
	sessionMiddleware({
		store,
		encryptionKey: sessionKey,
		expireAfterSeconds: 60 * 60 * 24,
		cookieOptions: {
			sameSite: "Lax",
			path: "/",
			httpOnly: true,
		},
	})
);

app.get("/", (c) => {
	return c.text("Hello Hono!");
});

app.post("register", zValidator("json", registerSchema), async (c) => {
	const {
		username,
		password,
		name,
	}: {
		username: string;
		password: string;
		name: string;
	} = await c.req.json();

	if (
		!(
			/[A-Z]/.test(password) &&
			/[a-z]/.test(password) &&
			/[0-9]/.test(password) &&
			password.length >= 8
		)
	) {
		return c.json({ message: "Password not strong enough" }, 400);
	}
	const hashedPassword = await hash(password, {
		variant: Variant.Argon2id,
		version: Version.V13,
		timeCost: 10,
		lanes: 8,
	});
	const data = await db
		.insert(schema.users)
		.values({
			username,
			password: hashedPassword,
			name,
		})
		.returning();
	return c.json(data);
});

app.post("login", zValidator("json", loginSchema), async (c) => {
	const { username, password } = await c.req.json();
	const user = await db.query.users.findFirst({
		where: eq(schema.users.username, username),
	});
	if (!user) return c.text("Password or username incorrect", 401);
	const passwordCorrect = await verify(user.password, password);
	if (!passwordCorrect) return c.text("Password or username incorrect", 401);
	const session = c.get("session");
	const { password: _, ...leftUser } = user;
	session.set("user", leftUser);
	return c.json(leftUser);
});

app.get("logout", async (c) => {
	const session = c.get("session");
	session.deleteSession();
	return c.text("You have been logout");
});

app.get("profile", async (c) => {
	const session = c.get("session");
	const user = session.get("user");
	if (!user) return c.text("Unauthorized", 401);
	return c.json(user);
});

Deno.serve({ port: 3001 }, app.fetch);
