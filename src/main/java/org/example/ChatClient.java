package org.example;

import java.io.*;
import java.net.*;
import java.security.PublicKey;

public class ChatClient {
    private static final String HOST = "localhost";
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try {
            Socket socket = new Socket(HOST, PORT);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Read server's public key
            String publicKeyStr = in.readLine();
            PublicKey publicKey = ECCUtil.base64ToPublicKey(publicKeyStr);

            // Encrypt and send message
            String message = "Hello, server!";
            String encryptedMessage = ECCUtil.encryptECC(message, publicKey);
            out.println(encryptedMessage);

            System.out.println("Sent: " + message);

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
