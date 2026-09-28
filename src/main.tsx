import React from "react";
import ReactDOM from "react-dom/client";
import OrbitDeliveryHero from "@/components/ui/orbit-delivery-hero";

const rootElement = document.getElementById("orbit-hero-root");
if (rootElement) {
  ReactDOM.createRoot(rootElement).render(
    <React.StrictMode>
      <OrbitDeliveryHero theme="auto" />
    </React.StrictMode>
  );
}
