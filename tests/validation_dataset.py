VALIDATION_DATASET = [
    {
        "name": "python_good",
        "language": "python",
        "code": """def add_numbers(a: int, b: int) -> int:
    # Adds two integers and returns the result
    return a + b
""",
        "expected_findings": []
    },
    {
        "name": "python_sqli_and_long_method",
        "language": "python",
        "code": """import sqlite3

def get_user_details_and_process_reports_with_long_method_signature(db_path, user_id, report_type, output_format, verbose_logging=False):
    # This is a very long method designed to trigger long parameter lists and SQL Injection
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # SQL injection via string formatting
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    cursor.execute(query)
    row = cursor.fetchone()
    
    # Let's make this method > 50 lines to trigger Long Method smell
    a = 1
    b = 2
    c = 3
    d = 4
    e = 5
    f = 6
    g = 7
    h = 8
    i = 9
    j = 10
    k = 11
    l = 12
    m = 13
    n = 14
    o = 15
    p = 16
    q = 17
    r = 18
    s = 19
    t = 20
    u = 21
    v = 22
    w = 23
    x = 24
    y = 25
    z = 26
    aa = 27
    bb = 28
    cc = 29
    dd = 30
    ee = 31
    ff = 32
    gg = 33
    hh = 34
    ii = 35
    jj = 36
    kk = 37
    ll = 38
    mm = 39
    nn = 40
    oo = 41
    pp = 42
    qq = 43
    rr = 44
    ss = 45
    tt = 46
    uu = 47
    vv = 48
    ww = 49
    xx = 50
    yy = 51
    zz = 52
    
    return row
""",
        "expected_findings": [
            {"id": "QLY-001"}, # Long Method
            {"id": "QLY-002"}, # Long Parameter List
            {"id": "SEC-002"}  # SQL Injection
        ]
    },
    {
        "name": "python_lazy_class",
        "language": "python",
        "code": """class ShortClass:
    def method_one(self):
        pass
""",
        "expected_findings": [
            {"id": "QLY-016"}  # Lazy Class
        ]
    },
    {
        "name": "java_good",
        "language": "java",
        "code": """package com.example;

public class Calculator {
    /**
     * Adds two integers.
     */
    public int add(int a, int b) {
        return a + b;
    }
}
""",
        "expected_findings": []
    },
    {
        "name": "java_sqli_and_large_class",
        "language": "java",
        "code": """package com.example;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;

public class DatabaseManager {
    // Missing class Javadoc
    private Connection conn;

    public void queryUser(String userInputId) throws Exception {
        Statement stmt = conn.createStatement();
        // SQL injection via concatenation
        String query = "SELECT * FROM users WHERE id = '" + userInputId + "'";
        ResultSet rs = stmt.executeQuery(query);
    }
    
    // Add extra methods to make it a large class or god object
    public void m1() {}
    public void m2() {}
    public void m3() {}
    public void m4() {}
    public void m5() {}
    public void m6() {}
    public void m7() {}
    public void m8() {}
    public void m9() {}
    public void m10() {}
    public void m11() {}
}
""",
        "expected_findings": [
            {"id": "QLY-004"}, # Large Class Smell
            {"id": "SEC-002"}, # SQL Injection
            {"id": "QLY-BP-001"} # Missing Documentation
        ]
    }
]
