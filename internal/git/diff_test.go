package git

import "testing"

func TestParseDiffHunks(t *testing.T) {
	diff := `diff --git a/a.txt b/a.txt
index 1111111..2222222 100644
--- a/a.txt
+++ b/a.txt
@@ -1,3 +1,3 @@
 kept line
-old line
+new line
+AKIAIOSFODNN7EXAMPLE added
\ No newline at end of file
`
	lines := parseDiffHunks([]byte(diff))
	if len(lines) != 2 {
		t.Fatalf("expected 2 added lines, got %d: %+v", len(lines), lines)
	}
	if lines[0].Path != "a.txt" || lines[0].Line != 2 {
		t.Fatalf("bad first added line: %+v", lines[0])
	}
	if lines[1].Path != "a.txt" || lines[1].Line != 3 || lines[1].Text != "AKIAIOSFODNN7EXAMPLE added" {
		t.Fatalf("bad second added line: %+v", lines[1])
	}
}

func TestParseDiffHunksNewFile(t *testing.T) {
	diff := `diff --git a/new.txt b/new.txt
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/new.txt
@@ -0,0 +1,2 @@
+line one
+line two
`
	lines := parseDiffHunks([]byte(diff))
	if len(lines) != 2 {
		t.Fatalf("expected 2 added lines, got %d: %+v", len(lines), lines)
	}
	if lines[0].Line != 1 || lines[0].Text != "line one" {
		t.Fatalf("bad new-file first line: %+v", lines[0])
	}
	if lines[1].Line != 2 {
		t.Fatalf("bad new-file second line: %+v", lines[1])
	}
}
