import { z } from "zod";

export const registerSchema = z.object({
	username: z.string(),
	password: z.string(),
	name: z.string(),
});

export const loginSchema = z.object({
	username: z.string(),
	password: z.string(),
});
