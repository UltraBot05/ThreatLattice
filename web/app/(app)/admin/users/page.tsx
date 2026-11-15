import type { Metadata } from "next";
import { UserAdmin } from "./UserAdmin";

export const metadata: Metadata = { title: "Users" };

export default function AdminUsersPage() {
  return <UserAdmin />;
}
