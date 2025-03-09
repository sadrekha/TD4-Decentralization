import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { GetNodeRegistryBody } from "../registry/registry";
import {
  createRandomSymmetricKey,
  exportSymKey,
  importSymKey,
  rsaEncrypt,
  symEncrypt,
  generateRsaKeyPair,
  exportPubKey,
} from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // ----- User state -----
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] = [];

  // Status route
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // GET route to retrieve last received message
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // GET route to retrieve last sent message
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // GET route to retrieve the last circuit used (array of node IDs)
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  // POST route for receiving a message (e.g. forwarded from a node)
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });

  // POST route for sending a message via the onion network
  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body as SendMessageBody;
    lastSentMessage = message;

    // 1. Retrieve the node registry

    const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
    const registryData = (await registryResponse.json()) as GetNodeRegistryBody;
    const nodes = registryData.nodes as { nodeId: number; pubKey: string }[];

    // 2. Choose 3 distinct nodes at random
    if (nodes.length < 3) {
      res.status(500).send("Not enough nodes registered");
      return;
    }
    // Shuffle nodes array and take the first 3
    const shuffled = nodes.sort(() => Math.random() - 0.5);
    const circuitNodes = shuffled.slice(0, 3);
    lastCircuit = circuitNodes.map((node) => node.nodeId);

    // 3. Build layered encryption (onion encryption)
    // Starting payload is the original message.
    let payload = message;

    // Process nodes in reverse order (from the last node to the first)
    for (let i = circuitNodes.length - 1; i >= 0; i--) {
      const currentNode = circuitNodes[i];

      // Determine the destination for this layer:
      // For the last node in the circuit, destination is the target user's port.
      // Otherwise, destination is the next node's port.
      let destinationPort: number;
      if (i === circuitNodes.length - 1) {
        destinationPort = BASE_USER_PORT + destinationUserId;
      } else {
        destinationPort = BASE_ONION_ROUTER_PORT + circuitNodes[i + 1].nodeId;
      }
      const destStr = destinationPort.toString().padStart(10, "0");

      // Concatenate destination string with the current payload.
      const layeredMessage = destStr + payload;

      // Create a unique symmetric key for this layer.
      const symKey = await createRandomSymmetricKey();

      // Encrypt the concatenated string with the symmetric key.
      const symEncryptedPayload = await symEncrypt(symKey, layeredMessage);

      // Export the symmetric key to a base64 string.
      const exportedSymKey = await exportSymKey(symKey);

      // Encrypt the exported symmetric key with the node's RSA public key.
      const encryptedSymKey = await rsaEncrypt(exportedSymKey, currentNode.pubKey);

      // Concatenate the RSA-encrypted symmetric key and the sym encrypted payload.
      // (We use a colon delimiter to be able to split them later.)
      payload = encryptedSymKey + ":" + symEncryptedPayload;
    }

    // 4. Send the final payload to the entry node (first node in the circuit)
    const entryNodePort = BASE_ONION_ROUTER_PORT + circuitNodes[0].nodeId;
    await fetch(`http://localhost:${entryNodePort}/message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: payload }),
    });

    res.send("success");
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
