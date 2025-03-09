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

export async function simpleOnionRouter(nodeId: number) {
    const onionRouter = express();
    onionRouter.use(express.json());
    onionRouter.use(bodyParser.json());

    const { publicKey, privateKey } = await generateRsaKeyPair();
    const pubKeyStr = await exportPubKey(publicKey);
    await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nodeId, pubKey: pubKeyStr }),
    });

    let lastReceivedEncryptedMessage: string | null = null;
    let lastReceivedDecryptedMessage: string | null = null;
    let lastMessageDestination: number | null = null;

    onionRouter.get("/status", (req, res) => {
        res.send("live");
    });

    onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
        res.json({ result: lastReceivedEncryptedMessage });
    });

    onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
        res.json({ result: lastReceivedDecryptedMessage });
    });

    onionRouter.get("/getLastMessageDestination", (req, res) => {
        res.json({ result: lastMessageDestination });
    });

    onionRouter.get("/getPrivateKey", async (req, res) => {
        const prvKeyStr = await exportPrvKey(privateKey);
        res.json({ result: prvKeyStr });
    });

    onionRouter.post("/message", async (req, res) => {
        const { message } = req.body;
        lastReceivedEncryptedMessage = message;

        const delimiterIndex = message.indexOf(":");
        if (delimiterIndex === -1) {
            console.error("Invalid message format");
            res.status(400).send("Invalid message format");
            return;
        }
        const encryptedSymKey = message.slice(0, delimiterIndex);
        const symEncryptedPayload = message.slice(delimiterIndex + 1);

        const decryptedKeyStr = await rsaDecrypt(encryptedSymKey, privateKey);
        const symmetricKey = await importSymKey(decryptedKeyStr);

        const decryptedLayer = await symDecrypt(decryptedKeyStr, symEncryptedPayload);
        lastReceivedDecryptedMessage = decryptedLayer;

        const destinationStr = decryptedLayer.slice(0, 10);
        const innerPayload = decryptedLayer.slice(10);
        const nextDestination = parseInt(destinationStr, 10);
        lastMessageDestination = nextDestination;

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
            `Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`
        );
    });

    return server;
}
