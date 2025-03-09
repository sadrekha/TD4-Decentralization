import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
    nodeId: number;
    pubKey: string;
};

export type GetNodeRegistryBody = {
    nodes: Node[];
};

export async function launchRegistry() {
    const _registry = express();
    _registry.use(express.json());
    _registry.use(bodyParser.json());

    // In-memory storage for registered nodes
    const nodes: Node[] = [];

    // Status route
    _registry.get("/status", (req, res) => {
        res.send("live");
    });

    // Route for nodes to register themselves
    _registry.post("/registerNode", (req: Request, res: Response) => {
        const { nodeId, pubKey } = req.body as RegisterNodeBody;
        // Optionally check for duplicates (omitted for brevity)
        nodes.push({ nodeId, pubKey });
        res.send("success");
    });

    // Route for users to retrieve the registry
    _registry.get("/getNodeRegistry", (req, res) => {
        res.json({ nodes });
    });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
