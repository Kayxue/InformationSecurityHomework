import { Hono } from "hono";
import { getConnInfo } from "hono/bun";
import { CookieStore, Session, sessionMiddleware } from "hono-sessions";
import { drizzle } from "drizzle-orm/node-postgres";
import { link, sessionKey } from "./Config.ts";
import { hash, verify } from "argon2";
import * as schema from "./drizzle/schema.ts";
import { zValidator } from "@hono/zod-validator";
import {
	loginSchema,
	registerSchema,
	updatePasswordSchema,
} from "./ZodSchema.ts";
import { eq } from "drizzle-orm";
import { requireLoginMiddleware } from "./Middlewares.ts";

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
		timeCost: 10,
		parallelism: 8,
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
		columns: {
			passwordOld1: false,
			passwordOld2: false,
		},
	});
	const logObj = {
		username,
		ip: getConnInfo(c).remote.address as string,
		timestamp: new Date(),
		result: false,
	};
	if (!user) {
		await db.insert(schema.logs).values(logObj);
		return c.text("Password or username incorrect", 401);
	}
	const passwordCorrect = await verify(user.password, password);
	if (!passwordCorrect) {
		await db.insert(schema.logs).values(logObj);
		return c.text("Password or username incorrect", 401);
	}

	logObj.result = true;
	await db.insert(schema.logs).values(logObj);

	const session = c.get("session");
	const { password: _, ...leftUser } = user;
	session.set("user", leftUser);
	return c.json(leftUser);
});

app.get("logout", requireLoginMiddleware, async (c) => {
	const session = c.get("session");
	session.deleteSession();
	return c.text("You have been logout");
});

app.get("profile", requireLoginMiddleware, async (c) => {
	const session = c.get("session");
	const user = session.get("user");
	return c.json(user);
});

app.put(
	"updatePasswords",
	requireLoginMiddleware,
	zValidator("json", updatePasswordSchema),
	async (c) => {
		const session = c.get("session");
		const user = session.get("user");
		const { newPassword } = await c.req.json();
		if (
			!(
				/[A-Z]/.test(newPassword) &&
				/[a-z]/.test(newPassword) &&
				/[0-9]/.test(newPassword) &&
				newPassword.length >= 8
			)
		) {
			return c.json({ message: "Password not strong enough" }, 400);
		}
		//TODO: Check whether password is same with the password the user set for latest three times
		const hashedPassword = await hash(newPassword, {
			timeCost: 10,
			parallelism: 8,
		});
		await db
			.update(schema.users)
			.set({ password: hashedPassword })
			.where(eq(schema.users.id, user.id));
		return c.text("Updated password success");
	}
);

export default app
