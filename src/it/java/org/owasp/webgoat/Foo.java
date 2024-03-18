import io.github.pixee.security.SystemCommand;
import java.io.BufferedReader;

public class Foo {

  public void foo(BufferedReader reader, String c) {

    SystemCommand.runCommand(Runtime.getRuntime(), c);

  }
}
