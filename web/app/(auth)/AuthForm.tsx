"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Headline } from "@/components/motion/Headline";
import { Button } from "@/components/ui/Button";
import { Field, Input } from "@/components/ui/Field";
import { api } from "@/lib/client/api";
import { safeNext } from "@/lib/auth/redirect";
import { loginSchema, registerSchema } from "@/lib/auth/schemas";

export function AuthForm({ mode }: { mode: "login" | "register" }) {
  const router = useRouter();
  const params = useSearchParams();
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const isLogin = mode === "login";

  const onSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFormError(null);
    const data = Object.fromEntries(new FormData(e.currentTarget)) as Record<string, string>;
    const parsed = (isLogin ? loginSchema : registerSchema).safeParse(data);
    if (!parsed.success) {
      const next: Record<string, string> = {};
      for (const i of parsed.error.issues) next[String(i.path[0])] ??= i.message;
      setErrors(next);
      return;
    }
    setErrors({});
    setBusy(true);
    try {
      await api(`/api/auth/${mode}`, { method: "POST", body: JSON.stringify(parsed.data) });
      router.replace(safeNext(params.get("next")));
      router.refresh();
    } catch (err) {
      setFormError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[360px]">
      <p className="tl-label">THREATLATTICE / {isLogin ? "SIGN IN" : "REGISTER"}</p>
      <Headline className="mt-2 text-[40px] leading-[1.05]">{isLogin ? "Sign in" : "Create an account"}</Headline>
      <p className="mt-2 text-[13px] text-paper-dim">
        {isLogin ? "Use your username or email." : "New accounts are analysts. An admin can change roles."}
      </p>

      <form onSubmit={onSubmit} noValidate className="mt-8 flex flex-col gap-4">
        {isLogin ? (
          <Field label="Username or email" htmlFor="login" error={errors.login}>
            <Input id="login" name="login" autoComplete="username" autoFocus aria-invalid={!!errors.login} />
          </Field>
        ) : (
          <>
            <Field label="Username" htmlFor="username" error={errors.username}>
              <Input id="username" name="username" autoComplete="username" autoFocus aria-invalid={!!errors.username} />
            </Field>
            <Field label="Email" htmlFor="email" error={errors.email}>
              <Input id="email" name="email" type="email" autoComplete="email" aria-invalid={!!errors.email} />
            </Field>
          </>
        )}
        <Field label="Password" htmlFor="password" error={errors.password}>
          <Input
            id="password"
            name="password"
            type="password"
            autoComplete={isLogin ? "current-password" : "new-password"}
            aria-invalid={!!errors.password}
          />
        </Field>

        {formError ? (
          <p role="alert" className="border-l-2 border-hazard bg-hazard-dim px-3 py-2 text-[13px]">
            {formError}
          </p>
        ) : null}

        <Button type="submit" variant="primary" disabled={busy} className="mt-2 w-full">
          {busy ? (isLogin ? "Signing in" : "Creating account") : isLogin ? "Sign in" : "Create account"}
        </Button>
      </form>

      <p className="mt-6 text-[13px] text-paper-dim">
        {isLogin ? "No account yet? " : "Already registered? "}
        <Link
          href={isLogin ? "/register" : "/login"}
          className="text-paper underline underline-offset-4 hover:text-hazard"
        >
          {isLogin ? "Create one" : "Sign in"}
        </Link>
      </p>
    </div>
  );
}
