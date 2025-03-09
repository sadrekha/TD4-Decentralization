import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import {
    generateRsaKeyPair,
    exportPubKey,
    exportPrvKey,
    rsaDecrypt,
    symDecrypt,
    rsaEncrypt,
    importSymKey,
    exportSymKey,
} from "../crypto";

// Helper: pad a number to 10 characters with leading zeros.
function formatPort(port: number): string {
    return port.toString().padStart(10, "0");
}

export async function simpleOnionRouter(nodeId: number) {
    const onionRouter = express();
    onionRouter.use(express.json());
    onionRouter.use(bodyParser.json());

    // ----- Initialize node state -----
    // Generate RSA key pair for the node
    const { publicKey, privateKey } = await generateRsaKeyPair();
    // Register the node in the registry
    const pubKeyStr = await exportPubKey(publicKey);
    await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nodeId, pubKey: pubKeyStr }),
    });

    // State variables
    let lastReceivedEncryptedMessage: string | null = null;
    let lastReceivedDecryptedMessage: string | null = null;
    let lastMessageDestination: number | null = null;

    // ----- Routes -----

    // Status route
    onionRouter.get("/status", (req, res) => {
        res.send("live");
    });

    // GET route to retrieve the last received encrypted message
    onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
        res.json({ result: lastReceivedEncryptedMessage });
    });

    // GET route to retrieve the last received decrypted message
    onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
        res.json({ result: lastReceivedDecryptedMessage });
    });

    // GET route to retrieve the last message destination
    onionRouter.get("/getLastMessageDestination", (req, res) => {
        res.json({ result: lastMessageDestination });
    });

    // GET route to retrieve the node's private key (exported as base64)
    onionRouter.get("/getPrivateKey", async (req, res) => {
        const prvKeyStr = await exportPrvKey(privateKey);
        res.json({ result: prvKeyStr });
    });

    // POST route for receiving messages
    onionRouter.post("/message", async (req, res) => {
        const { message } = req.body;
        lastReceivedEncryptedMessage = message;

        // Our message format: "<rsaEncryptedSymKey>:<symEncryptedPayload>"
        const delimiter = ":";
        const parts = message.split(delimiter);
        if (parts.length !== 2) {
            console.error("Invalid message format");
            res.status(400).send("Invalid message format");
            return;
        }
        const [encryptedSymKey, symEncryptedPayload] = parts;

        // Decrypt the symmetric key using the node’s RSA private key
        const exportedSymKey = await rsaDecrypt(encryptedSymKey, privateKey);
        const symmetricKey = await importSymKey(exportedSymKey);

        // Decrypt the inner layer (which contains a destination string and an inner payload)
        const decryptedLayer = await symDecrypt(await exportSymKey(symmetricKey), symEncryptedPayload);
        lastReceivedDecryptedMessage = decryptedLayer;

        // The first 10 characters indicate the next destination port (as a string with leading zeros)
        const destinationStr = decryptedLayer.slice(0, 10);
        const innerPayload = decryptedLayer.slice(10);
        const nextDestination = parseInt(destinationStr, 10);
        lastMessageDestination = nextDestination;

        // Forward the inner payload to the next destination (could be another node or a user)
        const url = `http://localhost:${nextDestination}/message`;
        await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: innerPayload }),
        });

        res.send("success");
    });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
