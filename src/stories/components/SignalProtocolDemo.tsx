import React from "react";
import { Box, Typography, Card, CardContent } from "@mui/material";
import SecurityIcon from "@mui/icons-material/Security";

/**
 * Simple Signal Protocol demo component for bootstrap entry point
 * Used for module federation
 */
const SignalProtocolDemo: React.FC<{ children?: React.ReactNode }> = ({
  children,
}) => {
  return (
    <Card sx={{ maxWidth: 800, mx: "auto", mt: 4, p: 2 }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", mb: 2 }}>
          <SecurityIcon sx={{ mr: 1 }} />
          <Typography variant="h5" component="h2">
            Signal Protocol WASM
          </Typography>
        </Box>
        <Typography variant="body1" paragraph>
          Signal Protocol implementation in Rust compiled to WebAssembly.
        </Typography>
        {children && <Box sx={{ mt: 2 }}>{children}</Box>}
      </CardContent>
    </Card>
  );
};

export default SignalProtocolDemo;
