/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package dos;

import java.util.ArrayList;
import java.io.File;
import java.io.FileOutputStream;
import weka.core.Instances;
import weka.classifiers.Evaluation;
import weka.classifiers.Classifier;
import java.io.BufferedReader;
import java.io.FileReader;
import weka.classifiers.rules.DecisionTable;
import weka.attributeSelection.GeneticSearch;
/**
 *
 * @author seabirds
 */
public class DataFrame extends javax.swing.JFrame {

    /**
     * Creates new form DataFrame
     */
    String data;
    public DataFrame(String dd) 
    {
        initComponents();
        data=dd;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        jButton1 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jPanel1.setBackground(new java.awt.Color(255, 255, 255));

        jLabel1.setFont(new java.awt.Font("Algerian", 0, 24)); // NOI18N
        jLabel1.setText("Encoded Data");

        jTable1.setFont(new java.awt.Font("Cambria Math", 0, 15)); // NOI18N
        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        jTable1.setRowHeight(26);
        jScrollPane1.setViewportView(jTable1);

        jButton1.setFont(new java.awt.Font("Cambria Math", 0, 15)); // NOI18N
        jButton1.setText("Rules");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(208, 208, 208)
                        .addComponent(jLabel1))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(40, 40, 40)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 533, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(53, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(jButton1)
                .addGap(259, 259, 259))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(25, 25, 25)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 29, Short.MAX_VALUE)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 374, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jButton1)
                .addGap(12, 12, 12))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
        try
        {
            String cls="";
            
            String s1[]=data.split("\n");
            String col[]=s1[0].split("\t");
            String s2[]=s1[1].split("\t");
            String dd="@relation dd\n";
            for(int i=0;i<s2.length;i++)
            {
                if(s2[i].equals("sym"))
                {
                    
                    ArrayList at=new ArrayList();
                    for(int j=2;j<s1.length;j++)
                    {
                        String a1[]=s1[j].split("\t");
                        String g1=a1[i];
                        if(!at.contains(g1))
                            at.add(g1);
                    }
                    String ga=at.toString().replace("[", "");
                    ga=ga.replace("]","");
                    dd=dd+"@attribute "+col[i]+" {"+ga+"}\n";
                    cls=ga;
                }
                else
                    dd=dd+"@attribute "+col[i]+" numeric\n";
            }
            dd=dd+"@data\n";
            for(int j=2;j<s1.length;j++)
            {
                dd=dd+s1[j].replace("\t", ",")+"\n";
            }
            dd=dd.trim();
            File fe=new File("dos.arff");
            FileOutputStream fos=new FileOutputStream(fe);
            fos.write(dd.getBytes());
            fos.close();
            ArrayList rlt1=new ArrayList();
            
            for(int i=2;i<s1.length;i++)
            {
                if(!rlt1.contains(s1[i]))
                    rlt1.add(s1[i]);
            }
            
            System.out.println(rlt1.size()+" : "+s1.length);
            String rules="";
            for(int i=0;i<rlt1.size();i++)
            {
                String g1=rlt1.get(i).toString();
                String g2[]=g1.split("\t");
                String r1="If ";
                for(int j=0;j<g2.length-1;j++)
                {
                    r1=r1+col[j]+" = "+g2[j]+" and ";
                }
                r1=r1.substring(0, r1.lastIndexOf("and"));
                r1=r1+" then "+col[col.length-1]+" = "+g2[g2.length-1];
                System.out.println(r1);
                rules=rules+r1+"\n";
            }
            
         
            
            Instances idata = new Instances(new BufferedReader(new FileReader("dos.arff")));
            DecisionTable dt=new DecisionTable();
            int cIdx=idata.numAttributes()-1;
            idata.setClassIndex(cIdx);
		
            GeneticSearch gs=new GeneticSearch();  
	
            gs.setStartSet("1");
            String[] options = new String[3];
            options[0]="- X 1";
            options[1]="- E mae";
            options[2]="-S weka.attributeSelection.GeneticSearch -Z 20 -G 20 -C 0.3 -M 0.033 -R 20 -S 1";
		
            dt.setOptions(options);
            dt.setSearch(gs);
		
            dt. setDisplayRules(true); 
            dt.buildClassifier(idata);
	
            System.out.println(dt.toString());
            GeneticFrame gf=new GeneticFrame();
            gf.jTextArea1.setText(dt.toString());
            gf.setTitle("Rules");
            gf.setResizable(false);
            gf.setVisible(true);
            
               RuleFrame rf=new RuleFrame(this,cls);
            rf.jTextArea1.setText(rules);
            rf.setTitle("Rules");
            rf.setResizable(false);
            rf.setVisible(true);
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }//GEN-LAST:event_jButton1ActionPerformed

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
            java.util.logging.Logger.getLogger(DataFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(DataFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(DataFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(DataFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                //new DataFrame().setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    public javax.swing.JTable jTable1;
    // End of variables declaration//GEN-END:variables
}
