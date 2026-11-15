/** UI scale levels, shared by the server layout (boot script) and the client TextSize control. */
export const UI_SCALES = [
  { value: "1", label: "S" },
  { value: "1.1", label: "M" },
  { value: "1.2", label: "L" },
  { value: "1.35", label: "XL" },
] as const;
export const DEFAULT_SCALE = "1.2";
export const SCALE_KEY = "tl-ui-scale";

/** Runs inline in <head> before paint, so the page never jumps size. Only whitelisted values are applied. */
export const SCALE_BOOT_SCRIPT = `try{var s=localStorage.getItem("${SCALE_KEY}");if(${JSON.stringify(
  UI_SCALES.map((s) => s.value),
)}.indexOf(s)>-1)document.documentElement.style.setProperty("--ui-scale",s)}catch(e){}`;
