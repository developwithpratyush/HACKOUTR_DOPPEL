import { createContext } from "react";
import type { BrandInfo } from "./types";

/** Registry brands by id (from /api/brands), for the family tree. Empty when the API is down. */
export const BrandsCtx = createContext<Record<string, BrandInfo>>({});

export const isMockVerdict = (v: { meta: { engine_version: string; mock: boolean } }) =>
  v.meta.engine_version.endsWith("-mock");
