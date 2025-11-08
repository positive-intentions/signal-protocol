import React from "react";
import { createRoot } from "react-dom/client";
import SignalProtocolDemo from "./stories/components/SignalProtocolDemo.tsx";

const App = () => {
  return (
    <div>
      <SignalProtocolDemo>positive-intentions</SignalProtocolDemo>
    </div>
  );
};

const container = document.getElementById("app");
const root = createRoot(container); // createRoot(container!) if you use TypeScript
root.render(<App />);
