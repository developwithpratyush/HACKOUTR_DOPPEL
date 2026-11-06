import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// Fonts are bundled (no Google Fonts call), so the console works with the internet off.
// Roboto is also the phone font the Human-Eye Renderer measures with.
import "@fontsource/inter/400.css";
import "@fontsource/inter/600.css";
import "@fontsource/inter/700.css";
import "@fontsource/inter/800.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/600.css";
import "@fontsource/plus-jakarta-sans/500.css";
import "@fontsource/plus-jakarta-sans/600.css";
import "@fontsource/plus-jakarta-sans/700.css";
import "@fontsource/plus-jakarta-sans/800.css";
import "@fontsource/inter/500.css";
import "@fontsource/jetbrains-mono/700.css";
import "@fontsource/roboto/400.css";
import "./index.css";
import App from "./App";

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
