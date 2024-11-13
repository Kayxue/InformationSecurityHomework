import { createMiddleware } from "hono/factory";

export const requireLoginMiddleware = createMiddleware(async (c, next) => {
	const session = c.get("session");
	const user = session.get("user");
	if (!user) return c.text("Unauthorized", 401);
	await next();
});
