import { z } from "zod";

/** Shared by the API (server) and the forms (client), so both check the same rules. */
export const usernameSchema = z
  .string()
  .trim()
  .min(3, "at least 3 characters")
  .max(50, "at most 50 characters")
  .regex(/^[a-zA-Z0-9_.-]+$/, "letters, digits, dot, dash and underscore only");

export const registerSchema = z.object({
  username: usernameSchema,
  email: z.email("enter a valid email").max(255),
  password: z.string().min(10, "at least 10 characters").max(128, "at most 128 characters"),
});

export const loginSchema = z.object({
  login: z.string().trim().min(1, "enter your username or email").max(255),
  password: z.string().min(1, "enter your password").max(128),
});
