//Ryan D. 12/14/2019.
//Imports.
import java.awt.event.KeyEvent;
import java.util.HashSet;
import javax.swing.JDesktopPane;
import java.util.Random;
import java.util.Scanner;
import java.util.Set;
import javax.swing.JOptionPane;
import javax.swing.JDialog;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class Encrypt extends javax.swing.JFrame {
    int randNumber = 0;        
    byte[] cipherTextArray;
    static byte[] cipherTextToDecrypt;
        
    public Encrypt() {
        initComponents();
        cmdDecrypt.setVisible(false);// Used for setting cmdDecrypt to not be visible.
// Get an instance of the RSA key generator.
    try {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);

        // Generate the KeyPair.
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Get the public and private key.
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // Get the RSAPublicKeySpec and RSAPrivateKeySpec.
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        
        // Saving the Key to the file.
        saveKeyToFile("public.key", publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
        saveKeyToFile("private.key", privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());
    }
    catch (Exception e)
    {
        e.printStackTrace();
    }
    }

    public static void SetEncryptedText(String Original){
        try {// Base64.getEncoder().encodeToString(cipherTextArray.
            cipherTextToDecrypt = Base64.getDecoder().decode(Original);
            
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
    
    public static String getDecryptedText() throws IOException{
        String decryptedText = "Unable to Decrypt Text";
        try {// Try and catch used genrating the private key.
             decryptedText = decrypt(cipherTextToDecrypt, "private.key");
        }
        catch (Exception e){
            e.printStackTrace();
        }        
        finally {
               return decryptedText;

        }
    }

    public static void saveKeyToFile(String fileName, BigInteger modulus, BigInteger exponent) throws IOException
    { // Get a reference to a file stream on the disk in preparation for writing the key
        ObjectOutputStream ObjOutputStream = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try
        {// Try and catch used for saving the key to a local file.
            ObjOutputStream.writeObject(modulus);
            ObjOutputStream.writeObject(exponent);
        } catch (Exception e)
        {
            e.printStackTrace();
        } finally
        {
            // Close the object stream.
            ObjOutputStream.close();
        }
    }

    public static Key readKeyFromFile(String keyFileName) throws IOException
    {
        Key key = null;
        InputStream inputStream = new FileInputStream(keyFileName);
        ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream));
        try
        {// Try and catch with an if/else statement used for performing RSA encrytion.
            BigInteger modulus = (BigInteger) objectInputStream.readObject();
            BigInteger exponent = (BigInteger) objectInputStream.readObject();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            if (keyFileName.startsWith("public"))
                key = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
            else
                key = keyFactory.generatePrivate(new RSAPrivateKeySpec(modulus, exponent));

        } catch (Exception e)
        {
            e.printStackTrace();
        } finally
        { // Close the object stream.
            objectInputStream.close();
        }
        return key;
    }

    public static byte[] encrypt(String plainText, String fileName) throws Exception
    {
        Key publicKey = readKeyFromFile("public.key");

        // Get Cipher Instance.
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        // Initialize Cipher for ENCRYPT_MODE.
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Perform Encryption.
        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        return cipherText;
    }

    public static String decrypt(byte[] cipherTextArray, String fileName) throws Exception
    {
        Key privateKey = readKeyFromFile("private.key");

        // Get Cipher Instance.
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        // Initialize Cipher for DECRYPT_MODE.
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Perform Decryption.
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);

        return new String(decryptedTextArray);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        pnlEncryptor = new javax.swing.JPanel();
        lblTitle = new javax.swing.JLabel();
        cmdExit = new javax.swing.JButton();
        cmdEnter = new javax.swing.JButton();
        cmdClear2 = new javax.swing.JButton();
        cmdClear1 = new javax.swing.JButton();
        txtOriginal = new javax.swing.JTextField();
        txtEncrypted = new javax.swing.JTextField();
        lblOriginal = new javax.swing.JLabel();
        lblEncrypted = new javax.swing.JLabel();
        lblFeedback = new javax.swing.JLabel();
        cmdDecrypt = new javax.swing.JButton();
        lblImg1 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        pnlEncryptor.setBackground(new java.awt.Color(255, 102, 204));
        pnlEncryptor.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        lblTitle.setFont(new java.awt.Font("Sitka Text", 1, 14)); // NOI18N
        lblTitle.setText("RSA Text Encryptor");
        pnlEncryptor.add(lblTitle, new org.netbeans.lib.awtextra.AbsoluteConstraints(220, 0, -1, -1));

        cmdExit.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        cmdExit.setText("Exit");
        cmdExit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdExitActionPerformed(evt);
            }
        });
        pnlEncryptor.add(cmdExit, new org.netbeans.lib.awtextra.AbsoluteConstraints(472, 363, 65, 25));

        cmdEnter.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        cmdEnter.setText("Enter");
        cmdEnter.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdEnterActionPerformed(evt);
            }
        });
        pnlEncryptor.add(cmdEnter, new org.netbeans.lib.awtextra.AbsoluteConstraints(472, 327, 65, 25));

        cmdClear2.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        cmdClear2.setText("Clear");
        cmdClear2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdClear2ActionPerformed(evt);
            }
        });
        pnlEncryptor.add(cmdClear2, new org.netbeans.lib.awtextra.AbsoluteConstraints(472, 288, 65, 25));

        cmdClear1.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        cmdClear1.setText("Clear");
        cmdClear1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdClear1ActionPerformed(evt);
            }
        });
        pnlEncryptor.add(cmdClear1, new org.netbeans.lib.awtextra.AbsoluteConstraints(472, 252, 65, 25));

        txtOriginal.setFont(new java.awt.Font("Yu Gothic", 0, 10)); // NOI18N
        txtOriginal.setMaximumSize(new java.awt.Dimension(7, 23));
        txtOriginal.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                txtOriginalKeyPressed(evt);
            }
        });
        pnlEncryptor.add(txtOriginal, new org.netbeans.lib.awtextra.AbsoluteConstraints(167, 254, 295, -1));

        txtEncrypted.setEditable(false);
        txtEncrypted.setFont(new java.awt.Font("Yu Gothic", 0, 10)); // NOI18N
        txtEncrypted.setMaximumSize(new java.awt.Dimension(7, 23));
        txtEncrypted.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtEncryptedActionPerformed(evt);
            }
        });
        txtEncrypted.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                txtEncryptedKeyPressed(evt);
            }
        });
        pnlEncryptor.add(txtEncrypted, new org.netbeans.lib.awtextra.AbsoluteConstraints(167, 293, 295, -1));

        lblOriginal.setFont(new java.awt.Font("Yu Gothic", 0, 12)); // NOI18N
        lblOriginal.setText("Original:");
        pnlEncryptor.add(lblOriginal, new org.netbeans.lib.awtextra.AbsoluteConstraints(20, 255, 108, -1));

        lblEncrypted.setFont(new java.awt.Font("Yu Gothic", 0, 12)); // NOI18N
        lblEncrypted.setText("Encrypted:");
        pnlEncryptor.add(lblEncrypted, new org.netbeans.lib.awtextra.AbsoluteConstraints(20, 294, -1, -1));

        lblFeedback.setFont(new java.awt.Font("Yu Gothic UI Semibold", 1, 10)); // NOI18N
        pnlEncryptor.add(lblFeedback, new org.netbeans.lib.awtextra.AbsoluteConstraints(167, 230, 381, 16));

        cmdDecrypt.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        cmdDecrypt.setText("Decrypt");
        cmdDecrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdDecryptActionPerformed(evt);
            }
        });
        pnlEncryptor.add(cmdDecrypt, new org.netbeans.lib.awtextra.AbsoluteConstraints(263, 343, -1, -1));

        lblImg1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/lock.gif"))); // NOI18N
        pnlEncryptor.add(lblImg1, new org.netbeans.lib.awtextra.AbsoluteConstraints(192, 46, -1, -1));

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(pnlEncryptor, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(pnlEncryptor, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void txtOriginalKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtOriginalKeyPressed
        String value = txtOriginal.getText();
        int l = value.length();
        if (evt.getKeyChar() == KeyEvent.VK_BACK_SPACE ||  evt.getKeyChar() == KeyEvent.VK_DELETE)
            // Always accept backspace and delete.
            txtOriginal.setEditable(true);
        else if (l < 25)
            // Accept a character if they haven't typed more than 25 characters already.
            txtOriginal.setEditable(true);
        else 
            txtOriginal.setEditable(false);
    }//GEN-LAST:event_txtOriginalKeyPressed

    private void txtEncryptedKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtEncryptedKeyPressed
        String value = txtEncrypted.getText();
        int l = value.length();
        if (evt.getKeyChar() == KeyEvent.VK_BACK_SPACE ||  evt.getKeyChar() == KeyEvent.VK_DELETE)
            // Always accept backspace and delete.
            txtEncrypted.setEditable(true);
        else if (l < 25)
            // Accept a character if they haven't typed more than 9 characters already.
            txtEncrypted.setEditable(true);
        else 
            txtEncrypted.setEditable(false);
    }//GEN-LAST:event_txtEncryptedKeyPressed

    private void cmdClear1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdClear1ActionPerformed
    txtOriginal.setText(""); // txtOriginal will clear when the user interacts with this button.
    }//GEN-LAST:event_cmdClear1ActionPerformed

    private void cmdClear2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdClear2ActionPerformed
    txtEncrypted.setText(""); // txtEncrypted will clear when the user interacts with this button.
    }//GEN-LAST:event_cmdClear2ActionPerformed

    private void cmdEnterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdEnterActionPerformed
        String value = txtOriginal.getText();
        try {// Try and catch used for making cmdDecrypt visible.
            cipherTextArray = encrypt(value, "public.key");
            String encryptedText = Base64.getEncoder().encodeToString(cipherTextArray);
            txtEncrypted.setText(encryptedText);
            cmdDecrypt.setVisible(true);
        } catch (Exception e)
        {
        }
        
    }//GEN-LAST:event_cmdEnterActionPerformed

    private void cmdExitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdExitActionPerformed
        System.exit(0);// Program will close upon interaction.
    }//GEN-LAST:event_cmdExitActionPerformed

    private void cmdDecryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdDecryptActionPerformed
        try {
            Decrypt MyPopout = new Decrypt();                        
            MyPopout.SetParentReference(this);
            MyPopout.setVisible(true);
            //MyPopout.SetOriginalUsername(txtPass.getText());
            //String decryptedText = decrypt(cipherTextArray, "private.key");
           // MyPopout.SetOriginalPass(decryptedText);            
        } catch (Exception e) {
        }
   
    }//GEN-LAST:event_cmdDecryptActionPerformed

    private void txtEncryptedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtEncryptedActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtEncryptedActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Encrypt.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Encrypt.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Encrypt.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Encrypt.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Encrypt().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cmdClear1;
    private javax.swing.JButton cmdClear2;
    private javax.swing.JButton cmdDecrypt;
    private javax.swing.JButton cmdEnter;
    private javax.swing.JButton cmdExit;
    private javax.swing.JLabel lblEncrypted;
    private javax.swing.JLabel lblFeedback;
    private javax.swing.JLabel lblImg1;
    private javax.swing.JLabel lblOriginal;
    private javax.swing.JLabel lblTitle;
    private javax.swing.JPanel pnlEncryptor;
    private javax.swing.JTextField txtEncrypted;
    private javax.swing.JTextField txtOriginal;
    // End of variables declaration//GEN-END:variables
}
