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
public class project2 extends javax.swing.JFrame {
    int randNumber = 0;        

    public project2() {
        initComponents();
        cmdVerify.setVisible(false);

    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        pnlSignup = new javax.swing.JPanel();
        lblTitle = new javax.swing.JLabel();
        cmdExit = new javax.swing.JButton();
        cmdEnter = new javax.swing.JButton();
        cmdClear2 = new javax.swing.JButton();
        cmdClear1 = new javax.swing.JButton();
        txtUser = new javax.swing.JTextField();
        txtPass = new javax.swing.JTextField();
        lblUser = new javax.swing.JLabel();
        lblPass = new javax.swing.JLabel();
        lblFeedback = new javax.swing.JLabel();
        cmdVerify = new javax.swing.JButton();
        lblImg1 = new javax.swing.JLabel();
        lblImg2 = new javax.swing.JLabel();
        lblImg3 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        pnlSignup.setBackground(new java.awt.Color(0, 255, 255));

        lblTitle.setFont(new java.awt.Font("Sitka Text", 1, 14)); // NOI18N
        lblTitle.setText("Roblox SIgnup");

        cmdExit.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        cmdExit.setText("Exit");
        cmdExit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdExitActionPerformed(evt);
            }
        });

        cmdEnter.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        cmdEnter.setText("Enter");
        cmdEnter.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdEnterActionPerformed(evt);
            }
        });

        cmdClear2.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        cmdClear2.setText("Clear");
        cmdClear2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdClear2ActionPerformed(evt);
            }
        });

        cmdClear1.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        cmdClear1.setText("Clear");
        cmdClear1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdClear1ActionPerformed(evt);
            }
        });

        txtUser.setFont(new java.awt.Font("Yu Gothic", 0, 10)); // NOI18N
        txtUser.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                txtUserKeyPressed(evt);
            }
        });

        txtPass.setFont(new java.awt.Font("Yu Gothic", 0, 10)); // NOI18N
        txtPass.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                txtPassKeyPressed(evt);
            }
        });

        lblUser.setFont(new java.awt.Font("Yu Gothic", 0, 12)); // NOI18N
        lblUser.setText("Enter your email: ");

        lblPass.setFont(new java.awt.Font("Yu Gothic", 0, 12)); // NOI18N
        lblPass.setText("Enter your password: ");

        lblFeedback.setFont(new java.awt.Font("Yu Gothic UI Semibold", 1, 10)); // NOI18N

        cmdVerify.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        cmdVerify.setText("Verify");
        cmdVerify.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdVerifyActionPerformed(evt);
            }
        });

        lblImg1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/j.png"))); // NOI18N

        lblImg2.setIcon(new javax.swing.ImageIcon(getClass().getResource("/28.jpg"))); // NOI18N
        lblImg2.setText("jLabel1");

        lblImg3.setIcon(new javax.swing.ImageIcon("C:\\Users\\Dad\\Documents\\NetBeansProjects\\JavaProject2Dzeoba\\src\\4.jpg")); // NOI18N

        javax.swing.GroupLayout pnlSignupLayout = new javax.swing.GroupLayout(pnlSignup);
        pnlSignup.setLayout(pnlSignupLayout);
        pnlSignupLayout.setHorizontalGroup(
            pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlSignupLayout.createSequentialGroup()
                .addGroup(pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlSignupLayout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(cmdVerify)
                        .addGap(142, 142, 142))
                    .addGroup(pnlSignupLayout.createSequentialGroup()
                        .addGap(20, 20, 20)
                        .addGroup(pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(pnlSignupLayout.createSequentialGroup()
                                .addGroup(pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(lblPass)
                                    .addComponent(lblUser, javax.swing.GroupLayout.PREFERRED_SIZE, 108, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGroup(pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(txtUser, javax.swing.GroupLayout.DEFAULT_SIZE, 295, Short.MAX_VALUE)
                                    .addComponent(txtPass)))
                            .addGroup(pnlSignupLayout.createSequentialGroup()
                                .addComponent(lblImg3, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)))
                .addGroup(pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(cmdClear2, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(cmdExit, javax.swing.GroupLayout.DEFAULT_SIZE, 76, Short.MAX_VALUE)
                        .addComponent(cmdEnter, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addComponent(cmdClear1, javax.swing.GroupLayout.PREFERRED_SIZE, 76, javax.swing.GroupLayout.PREFERRED_SIZE)))
            .addGroup(pnlSignupLayout.createSequentialGroup()
                .addGap(220, 220, 220)
                .addComponent(lblTitle)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlSignupLayout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(lblFeedback, javax.swing.GroupLayout.PREFERRED_SIZE, 381, javax.swing.GroupLayout.PREFERRED_SIZE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlSignupLayout.createSequentialGroup()
                .addGap(51, 192, Short.MAX_VALUE)
                .addComponent(lblImg1)
                .addGap(75, 75, 75)
                .addComponent(lblImg2, javax.swing.GroupLayout.PREFERRED_SIZE, 96, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(35, 35, 35))
        );
        pnlSignupLayout.setVerticalGroup(
            pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlSignupLayout.createSequentialGroup()
                .addComponent(lblTitle)
                .addGroup(pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlSignupLayout.createSequentialGroup()
                        .addGap(28, 28, 28)
                        .addGroup(pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(lblImg1)
                            .addComponent(lblImg2)))
                    .addGroup(pnlSignupLayout.createSequentialGroup()
                        .addGap(7, 7, 7)
                        .addComponent(lblImg3)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 11, Short.MAX_VALUE)
                .addComponent(lblFeedback, javax.swing.GroupLayout.PREFERRED_SIZE, 16, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(cmdClear1, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(txtUser, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(lblUser)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(cmdClear2)
                    .addComponent(txtPass, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblPass))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlSignupLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlSignupLayout.createSequentialGroup()
                        .addComponent(cmdEnter)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(cmdExit))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlSignupLayout.createSequentialGroup()
                        .addComponent(cmdVerify)
                        .addGap(20, 20, 20))))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(pnlSignup, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(pnlSignup, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void txtUserKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtUserKeyPressed
        String value = txtUser.getText();
        int l = value.length();
        if (evt.getKeyChar() == KeyEvent.VK_BACK_SPACE ||  evt.getKeyChar() == KeyEvent.VK_DELETE)
            // Always accept backspace and delete.
            txtUser.setEditable(true);
        else if (l < 25)
            // Accept a character if they haven't typed more than 25 characters already.
            txtUser.setEditable(true);
        else 
            txtUser.setEditable(false);
    }//GEN-LAST:event_txtUserKeyPressed

    private void txtPassKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtPassKeyPressed
        String value = txtPass.getText();
        int l = value.length();
        if (evt.getKeyChar() == KeyEvent.VK_BACK_SPACE ||  evt.getKeyChar() == KeyEvent.VK_DELETE)
            // Always accept backspace and delete.
            txtPass.setEditable(true);
        else if (l < 25)
            // Accept a character if they haven't typed more than 9 characters already.
            txtPass.setEditable(true);
        else 
            txtPass.setEditable(false);
    }//GEN-LAST:event_txtPassKeyPressed

    private void cmdClear1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdClear1ActionPerformed
    txtUser.setText(""); // txtUser will clear when the user interacts with this button.
    }//GEN-LAST:event_cmdClear1ActionPerformed

    private void cmdClear2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdClear2ActionPerformed
    txtPass.setText(""); // txtpass will clear when the user interacts with this button.
    }//GEN-LAST:event_cmdClear2ActionPerformed

    private void cmdEnterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdEnterActionPerformed
        String value = txtPass.getText();
        Random rand = new Random(); 
        randNumber = rand.nextInt(100) + 1; 
        int l = value.length();
        if (l  >= 5 && l <= 10) {
            lblFeedback.setText("Your password is: " + value + randNumber + "! Click verify to create your account.");
            cmdVerify.setVisible(true);
        }
        else 
            lblFeedback.setText("Your password doesn't meet our criteria..");
    }//GEN-LAST:event_cmdEnterActionPerformed

    private void cmdExitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdExitActionPerformed
        System.exit(0);
    }//GEN-LAST:event_cmdExitActionPerformed

    private void cmdVerifyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdVerifyActionPerformed
                userPopout MyPopout = new userPopout();                
                MyPopout.setVisible(true);
                MyPopout.SetOriginalUsername(txtUser.getText());
                MyPopout.SetOriginalPass(txtPass.getText() + randNumber);        
    }//GEN-LAST:event_cmdVerifyActionPerformed

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
            java.util.logging.Logger.getLogger(project2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(project2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(project2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(project2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new project2().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cmdClear1;
    private javax.swing.JButton cmdClear2;
    private javax.swing.JButton cmdEnter;
    private javax.swing.JButton cmdExit;
    private javax.swing.JButton cmdVerify;
    private javax.swing.JLabel lblFeedback;
    private javax.swing.JLabel lblImg1;
    private javax.swing.JLabel lblImg2;
    private javax.swing.JLabel lblImg3;
    private javax.swing.JLabel lblPass;
    private javax.swing.JLabel lblTitle;
    private javax.swing.JLabel lblUser;
    private javax.swing.JPanel pnlSignup;
    private javax.swing.JTextField txtPass;
    private javax.swing.JTextField txtUser;
    // End of variables declaration//GEN-END:variables
}