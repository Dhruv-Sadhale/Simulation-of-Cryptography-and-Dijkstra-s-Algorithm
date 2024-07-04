package org.example;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class ChatApplicationGUI {
    private JPanel mainPanel;
    private JTextArea chatArea;
    private JTextField messageField;
    private JButton sendButton;

    private SecretKey aesKey;
    private KeyPair eccKeyPair;

    private Graph graph;
    private DijkstraAlgorithm dijkstra;

    public ChatApplicationGUI() {
        initComponents();
        try {
            aesKey = AESUtil.generateAESKey();
            eccKeyPair = ECCUtil.generateECCKeyPair();
            setupGraph();
        } catch (Exception e) {
            e.printStackTrace();
        }

        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String message = messageField.getText();

                    // Calculate the checksum of the original message
                    String checksum = calculateChecksum(message);

                    // Encrypt the message
                    String encryptedMessage = AESUtil.encrypt(message, aesKey);

                    // Simulate sending the message and displaying the output
                    simulateMessageRouting(message, encryptedMessage, checksum);

                    // Clear the input field
                    messageField.setText("");
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });
    }

    private void initComponents() {
        mainPanel = new JPanel();
        chatArea = new JTextArea(20, 50);
        chatArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        messageField = new JTextField(40);
        sendButton = new JButton("Send");
        mainPanel.add(scrollPane);
        mainPanel.add(messageField);
        mainPanel.add(sendButton);
    }

    private void setupGraph() {
        Node nodeA = new Node("A");
        Node nodeB = new Node("B");
        Node nodeC = new Node("C");
        Node nodeD = new Node("D");

        Edge edgeAB = new Edge(nodeA, nodeB, 1);
        Edge edgeAC = new Edge(nodeA, nodeC, 4);
        Edge edgeBD = new Edge(nodeB, nodeD, 2);
        Edge edgeCD = new Edge(nodeC, nodeD, 1);

        List<Node> nodes = Arrays.asList(nodeA, nodeB, nodeC, nodeD);
        List<Edge> edges = Arrays.asList(edgeAB, edgeAC, edgeBD, edgeCD);

        graph = new Graph(nodes, edges);
        dijkstra = new DijkstraAlgorithm(graph);
    }

    private String calculateChecksum(String message) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(message.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    private void simulateMessageRouting(String originalMessage, String encryptedMessage, String checksum) {
        Node senderNode = new Node("A");

        dijkstra.execute(senderNode);

        for (Node node : graph.getNodes()) {
            if (!node.equals(senderNode)) {
                LinkedList<Node> path = dijkstra.getPath(node);
                int timeTaken = dijkstra.getShortestDistance(node);
                if (path != null) {
                    // Decrypt the message
                    String decryptedMessage = decryptMessage(encryptedMessage);

                    // Verify checksum
                    String receivedChecksum = calculateChecksum(decryptedMessage);
                    boolean checksumMatch = checksum.equals(receivedChecksum);

                    chatArea.append("Message sent to Node " + node.getName() + " via path: " + path + "\n");
                    chatArea.append("Time taken: " + timeTaken + " units\n");
                    chatArea.append("Original Message: " + originalMessage + "\n");
                    chatArea.append("Encrypted Message: " + encryptedMessage + "\n");
                    chatArea.append("Decrypted Message: " + decryptedMessage + "\n");
                    chatArea.append("Checksum Match: " + checksumMatch + "\n\n");
                } else {
                    chatArea.append("Node " + node.getName() + " is not reachable from Node A\n");
                }
            }
        }
    }

    private String decryptMessage(String encryptedMessage) {
        try {
            return AESUtil.decrypt(encryptedMessage, aesKey);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                JFrame frame = new JFrame("Chat Application");
                ChatApplicationGUI chatApp = new ChatApplicationGUI();
                frame.setContentPane(chatApp.getMainPanel());
                frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                frame.pack();
                frame.setVisible(true);
            }
        });
    }
}
