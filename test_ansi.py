from ansi2html import Ansi2HTMLConverter

def test_ansi_conversion():
    conv = Ansi2HTMLConverter(inline=True)
    
    # Test case 1: Simple string
    line1 = "Hello World"
    html1 = conv.convert(line1, full=False)
    print(f"Original: {line1}")
    print(f"HTML: {html1}")
    print(f"SSE: data: {html1}\\n\\n")
    
    # Test case 2: ANSI color
    line2 = "\x1b[31mRed Text\x1b[0m"
    html2 = conv.convert(line2, full=False)
    print(f"Original: {repr(line2)}")
    print(f"HTML: {html2}")
    print(f"SSE: data: {html2}\\n\\n")
    
    # Test case 3: Newline handling
    line3 = "Line with newline\n"
    html3 = conv.convert(line3, full=False)
    print(f"Original: {repr(line3)}")
    print(f"HTML: {repr(html3)}")

if __name__ == "__main__":
    test_ansi_conversion()
