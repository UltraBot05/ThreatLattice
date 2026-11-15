"use client";

import * as RS from "@radix-ui/react-select";
import { CaretDown, Check } from "@phosphor-icons/react";
import { Children, isValidElement, type ChangeEvent, type ReactElement, type ReactNode } from "react";

/**
 * Styled dropdown (Radix Select): the native <select> popup is drawn by the
 * OS and ignores our theme. Drop-in for the old native version: same props
 * (value / defaultValue / onChange(e) with e.target.value / <option>
 * children), so call sites did not change.
 * Keyboard: Enter/Space/Arrow opens, arrows move, type-ahead, Esc closes.
 * Radix reserves "" as "no value", so an <option value=""> ("All years",
 * "Relevance") is mapped to a sentinel internally and back on change.
 */
const EMPTY = "__tl_empty__";
const toRadix = (v: string | undefined) => (v === "" ? EMPTY : v);
const fromRadix = (v: string) => (v === EMPTY ? "" : v);

type OptionEl = ReactElement<{ value?: string | number; children?: ReactNode; disabled?: boolean }>;

export interface SelectProps {
  value?: string;
  defaultValue?: string;
  onChange?: (e: ChangeEvent<HTMLSelectElement>) => void;
  children: ReactNode;
  className?: string;
  id?: string;
  name?: string;
  disabled?: boolean;
  placeholder?: string;
  "aria-label"?: string;
}

export function Select({
  value,
  defaultValue,
  onChange,
  children,
  className = "",
  id,
  name,
  disabled,
  placeholder,
  "aria-label": ariaLabel,
}: SelectProps) {
  const options = Children.toArray(children)
    .filter((c): c is OptionEl => isValidElement(c) && c.type === "option")
    .map((o) => ({
      value: String(o.props.value ?? o.props.children ?? ""),
      label: o.props.children,
      disabled: o.props.disabled,
    }));

  const handle = (v: string) => {
    const val = fromRadix(v);
    // Shape it like a native change event so existing `e.target.value` handlers keep working.
    onChange?.({ target: { value: val, name }, currentTarget: { value: val, name } } as unknown as ChangeEvent<HTMLSelectElement>);
  };

  return (
    <RS.Root
      value={value === undefined ? undefined : toRadix(value)}
      defaultValue={defaultValue === undefined ? undefined : toRadix(defaultValue)}
      onValueChange={handle}
      disabled={disabled}
      name={name}
    >
      <RS.Trigger
        id={id}
        aria-label={ariaLabel}
        className={`group flex h-9 w-full items-center justify-between gap-2 rounded-[2px] border border-rule bg-ink-2 px-3 text-left text-[0.8125rem] text-paper outline-none transition-colors duration-150 hover:border-rule-strong focus-visible:border-hazard data-[state=open]:border-hazard data-[placeholder]:text-paper-faint disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
      >
        <span className="min-w-0 truncate">
          <RS.Value placeholder={placeholder} />
        </span>
        <RS.Icon asChild>
          <CaretDown size={14} aria-hidden="true" className="shrink-0 text-paper-dim transition-transform duration-150 group-data-[state=open]:rotate-180" />
        </RS.Icon>
      </RS.Trigger>
      <RS.Portal>
        <RS.Content
          position="popper"
          sideOffset={4}
          className="tl-select-content z-50 max-h-[min(20rem,var(--radix-select-content-available-height))] min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-[2px] border border-rule-strong bg-ink-2"
        >
          <RS.Viewport className="p-1">
            {options.map((o) => (
              <RS.Item
                key={o.value}
                value={toRadix(o.value) as string}
                disabled={o.disabled}
                className="relative flex h-8 cursor-pointer select-none items-center rounded-[2px] pl-7 pr-3 text-[0.8125rem] text-paper-dim outline-none data-[disabled]:pointer-events-none data-[disabled]:opacity-40 data-[highlighted]:bg-ink-3 data-[highlighted]:text-paper data-[state=checked]:text-paper"
              >
                <RS.ItemIndicator className="absolute left-2 inline-flex items-center text-hazard">
                  <Check size={12} weight="bold" aria-hidden="true" />
                </RS.ItemIndicator>
                <RS.ItemText>{o.label}</RS.ItemText>
              </RS.Item>
            ))}
          </RS.Viewport>
        </RS.Content>
      </RS.Portal>
    </RS.Root>
  );
}
