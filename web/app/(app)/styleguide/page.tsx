import type { Metadata } from "next";
import { StyleguideDemo } from "./StyleguideDemo";

export const metadata: Metadata = { title: "Styleguide" };

export default function StyleguidePage() {
  return <StyleguideDemo />;
}
