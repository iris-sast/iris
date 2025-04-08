/**
 * @name Find All Packages
 * @description Lists all packages in the Java project along with their class counts
 * @kind table
 * @id java/all-packages
 * @tags packages
 *       inventory
 */

 import java

 from Package p
 where p.fromSource()
 select p.getName()
 
