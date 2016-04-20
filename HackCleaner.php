<?php
/**
 * Shell based PHP script that searches for malcious code patterns using pcregrep.
 *
 * Intended to be run from the command line. This is a very simple script that searches for patterns I
 * have encountered very often in the Joomla and Worpress Content Management Systems (CMS). WARNING: Two
 * of these checks actually delete the entire file, because every time I have ever encountered them the
 * entire file was hacked code. The final check looks for a pattern that is typically embedded at the top
 * of a core file. Instead of deletion it will replace the entire first line of code, which is always
 * (in my case) an elongated, obsficated string that uses eval, base64decode, or other form of hacker
 * shennaniganry. So far this only searches for 4 different patterns I have encountered often, however
 * it is fairly simple to include a new pattern if you know how to use regular expression pattern matching.
 *
 * @category          Security - Intrusion Detection/Clean Up
 * @author            Xavious
 * @copyright         2016
 */
 
 /**
  * Check for command line parameters. Report Only "-r", or Clean Mode "-c" (DELETES/MODIFIES FILES)
  *
  * Possible values: -r, -c
  *
  * Example command (Report Only): php HackClaner.php -r
  *
  * @var argv
  *
  */
	if($argv[1] == '-r'){
		echo "Running in REPORT ONLY mode. (No files will be modified or deleted)\n";
		$mode = 'r';
	}
	else if($argv[1] == '-c'){
		echo "Running in CLEAN mode. Malicious files will be removed and embedded core files will be altered.)\n";
		$mode = 'c';
	}
	else{
		echo "Use -r for report only or -c to delete malicious files and clean altered core Joomla files.\nExample: \"php HackCleaner.php -r\"\n";
		exit();
	}
	
    echo "Checking for malicious php files matching expression..\n";
    $output = shell_exec('find -name \'*.php\' | xargs pcregrep -Mol \'<\?php\s+\$\w+\s=\s\d+;\sfunction\s\w+\(\$\w+,\s\$\w+\)\{\$\w+\s\=\s\'"\'\'"\';\sfor\(\$i=0;\s\$i\s<\sstrlen\(\$\w+\);\s\$i\+\+\)\{\$\w+\s\.=\sisset\(\$\w+\[\$\w+\[\$i\]\]\)\s\?\s\$\w+\[\$\w+\[\$i\]\]\s:\s\$\w+\[\$i\];\}\'');

    if($output != null){
		$files = preg_split('/\s+/', trim($output));
        echo "Malicious files found:\n";
        print_r($files);
		if($mode == 'c'){
			foreach($files as $file){
				echo "Removing file: $file \n";
				$command = "rm -f ".$file;
				shell_exec($command);
			}
		}
    }
    else{
        echo "No php files found matching expression.\n";
    }

    echo "Checking for malicious php files matching expression..\n";
    $output = shell_exec('find -name \'*.php\' | xargs pcregrep -Mol \'<\?php \$GLOBALS\[\'"\'"\'\w+\'"\'"\'\]\s=\s"\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+\\\x\w+";\'');

    if($output != null){
		$files = preg_split('/\s+/', trim($output));
        echo "Malicious files found:\n";
        print_r($files);
		if($mode == 'c'){
			foreach($files as $file){
				echo "Removing file: $file \n";
				$command = "rm -f ".$file;
				shell_exec($command);
			}
		}
    }
    else{
        echo "No php files found matching expression.\n";
    }

    echo "Checking for malicious php files matching expression..\n";
    $output = shell_exec('find -name \'*.php\' | xargs pcregrep -Mol \'<\?php\s+\$\w+=\$_COOKIE;\s+\$\w+=\$\w+\[\w+\];\s+if\(\$\w+\)\{\s+\$\w+=\$\w+\(\$\w+\[\w+\]\);\$\w+=\$\w+\(\$\w+\[\w+\]\);\$\w+=\$\w+\("",\$\w+\);\$\w+\(\);\s+}\'');

    if($output != null){
		$files = preg_split('/\s+/', trim($output));
        echo "Malicious files found:\n";
        print_r($files);
		if($mode == 'c'){
			foreach($files as $file){
				echo "Removing file: $file \n";
				$command = "rm -f ".$file;
				shell_exec($command);
			}
		}
    }
    else{
        echo "No php files found matching expression.\n";
    }
	
    echo "Checking for malicious code EMBEDDED in core Joomla files..\n";
    $output = shell_exec('find -name \'*.php\' | xargs pcregrep -Mol \'<\?php\s+\$GLOBALS\[\'"\'"\'\w+\'"\'"\'\];global\$\w+;\'');

    if($output !=null){
		$files = preg_split('/\s+/', trim($output));
        echo "Infected Joomla core files:\n";
        print_r($files);
		if($mode == 'c'){
			foreach($files as $file){
				echo "Fixing Joomla file: $file \n";
				$command = "sed -i '1s/.*/<?php/' ".$file;
				shell_exec($command);
			}
		}
    }
    else{
        echo "No infected Joomla core files found matching expression.\n";
    }

?>
