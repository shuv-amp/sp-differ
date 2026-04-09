// SPDX-License-Identifier: MIT
#include "semantic_json.hpp"

#include <cctype>
#include <fstream>
#include <sstream>

namespace sp_differ {
namespace {

// Minimal, dependency-free JSON parser and serializer for the semantic bridge.
// This keeps the runner implementation-agnostic and avoids linking a separate
// JSON library into every compiled surface.
class JsonParser {
 public:
  explicit JsonParser(std::string text) : text_(std::move(text)) {}

  JsonValue Parse() {
    SkipWhitespace();
    JsonValue value = ParseValue();
    SkipWhitespace();
    if (pos_ != text_.size()) {
      throw SemanticBridgeError("invalid JSON input: trailing characters");
    }
    return value;
  }

 private:
  JsonValue ParseValue() {
    if (pos_ >= text_.size()) {
      throw SemanticBridgeError("invalid JSON input: unexpected end of input");
    }
    const char ch = text_[pos_];
    if (ch == '{') {
      return ParseObject();
    }
    if (ch == '[') {
      return ParseArray();
    }
    if (ch == '"') {
      return JsonValue(ParseString());
    }
    if (ch == 't') {
      ConsumeLiteral("true");
      return JsonValue(true);
    }
    if (ch == 'f') {
      ConsumeLiteral("false");
      return JsonValue(false);
    }
    if (ch == 'n') {
      ConsumeLiteral("null");
      return JsonValue(nullptr);
    }
    if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch)) != 0) {
      return JsonValue(ParseInteger());
    }
    throw SemanticBridgeError("invalid JSON input: unexpected token");
  }

  JsonObject ParseObject() {
    Expect('{');
    JsonObject object;
    SkipWhitespace();
    if (TryConsume('}')) {
      return object;
    }
    while (true) {
      SkipWhitespace();
      if (pos_ >= text_.size() || text_[pos_] != '"') {
        throw SemanticBridgeError("invalid JSON input: object key must be a string");
      }
      std::string key = ParseString();
      SkipWhitespace();
      Expect(':');
      SkipWhitespace();
      object.emplace(std::move(key), ParseValue());
      SkipWhitespace();
      if (TryConsume('}')) {
        return object;
      }
      Expect(',');
      SkipWhitespace();
    }
  }

  JsonArray ParseArray() {
    Expect('[');
    JsonArray array;
    SkipWhitespace();
    if (TryConsume(']')) {
      return array;
    }
    while (true) {
      SkipWhitespace();
      array.push_back(ParseValue());
      SkipWhitespace();
      if (TryConsume(']')) {
        return array;
      }
      Expect(',');
      SkipWhitespace();
    }
  }

  std::string ParseString() {
    Expect('"');
    std::string out;
    while (pos_ < text_.size()) {
      const char ch = text_[pos_++];
      if (ch == '"') {
        return out;
      }
      if (ch == '\\') {
        if (pos_ >= text_.size()) {
          throw SemanticBridgeError("invalid JSON input: unterminated escape");
        }
        const char escaped = text_[pos_++];
        switch (escaped) {
          case '"':
          case '\\':
          case '/':
            out.push_back(escaped);
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'u': {
            const uint32_t codepoint = ParseUnicodeEscape();
            AppendUtf8(codepoint, &out);
            break;
          }
          default:
            throw SemanticBridgeError("invalid JSON input: bad escape sequence");
        }
        continue;
      }
      if (static_cast<unsigned char>(ch) < 0x20) {
        throw SemanticBridgeError("invalid JSON input: unescaped control character");
      }
      out.push_back(ch);
    }
    throw SemanticBridgeError("invalid JSON input: unterminated string");
  }

  uint32_t ParseUnicodeEscape() {
    if (pos_ + 4 > text_.size()) {
      throw SemanticBridgeError("invalid JSON input: truncated unicode escape");
    }
    uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      value <<= 4;
      const char ch = text_[pos_++];
      if (ch >= '0' && ch <= '9') {
        value |= static_cast<uint32_t>(ch - '0');
      } else if (ch >= 'a' && ch <= 'f') {
        value |= static_cast<uint32_t>(10 + ch - 'a');
      } else if (ch >= 'A' && ch <= 'F') {
        value |= static_cast<uint32_t>(10 + ch - 'A');
      } else {
        throw SemanticBridgeError("invalid JSON input: malformed unicode escape");
      }
    }
    return value;
  }

  static void AppendUtf8(uint32_t codepoint, std::string* out) {
    if (codepoint <= 0x7F) {
      out->push_back(static_cast<char>(codepoint));
      return;
    }
    if (codepoint <= 0x7FF) {
      out->push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
      out->push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
      return;
    }
    if (codepoint <= 0xFFFF) {
      out->push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
      out->push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
      return;
    }
    if (codepoint <= 0x10FFFF) {
      out->push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
      out->push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
      return;
    }
    throw SemanticBridgeError("invalid JSON input: unicode codepoint out of range");
  }

  int64_t ParseInteger() {
    const size_t start = pos_;
    if (text_[pos_] == '-') {
      ++pos_;
    }
    if (pos_ >= text_.size() || std::isdigit(static_cast<unsigned char>(text_[pos_])) == 0) {
      throw SemanticBridgeError("invalid JSON input: malformed number");
    }
    if (text_[pos_] == '0' && pos_ + 1 < text_.size() &&
        std::isdigit(static_cast<unsigned char>(text_[pos_ + 1])) != 0) {
      throw SemanticBridgeError("invalid JSON input: leading zero");
    }
    while (pos_ < text_.size() &&
           std::isdigit(static_cast<unsigned char>(text_[pos_])) != 0) {
      ++pos_;
    }
    if (pos_ < text_.size() && (text_[pos_] == '.' || text_[pos_] == 'e' || text_[pos_] == 'E')) {
      throw SemanticBridgeError("invalid JSON input: floating point numbers are unsupported");
    }
    const std::string token = text_.substr(start, pos_ - start);
    try {
      return std::stoll(token);
    } catch (...) {
      throw SemanticBridgeError("invalid JSON input: integer out of range");
    }
  }

  void ConsumeLiteral(const char* literal) {
    while (*literal != '\0') {
      if (pos_ >= text_.size() || text_[pos_] != *literal) {
        throw SemanticBridgeError("invalid JSON input: malformed literal");
      }
      ++pos_;
      ++literal;
    }
  }

  void SkipWhitespace() {
    while (pos_ < text_.size() &&
           std::isspace(static_cast<unsigned char>(text_[pos_])) != 0) {
      ++pos_;
    }
  }

  bool TryConsume(char expected) {
    if (pos_ < text_.size() && text_[pos_] == expected) {
      ++pos_;
      return true;
    }
    return false;
  }

  void Expect(char expected) {
    if (pos_ >= text_.size() || text_[pos_] != expected) {
      throw SemanticBridgeError("invalid JSON input: unexpected token");
    }
    ++pos_;
  }

  std::string text_;
  size_t pos_ = 0;
};

void AppendIndent(int indent, std::string* out) {
  out->append(static_cast<size_t>(indent), ' ');
}

void AppendEscapedString(const std::string& value, std::string* out) {
  out->push_back('"');
  for (unsigned char ch : value) {
    switch (ch) {
      case '"':
        out->append("\\\"");
        break;
      case '\\':
        out->append("\\\\");
        break;
      case '\b':
        out->append("\\b");
        break;
      case '\f':
        out->append("\\f");
        break;
      case '\n':
        out->append("\\n");
        break;
      case '\r':
        out->append("\\r");
        break;
      case '\t':
        out->append("\\t");
        break;
      default:
        if (ch < 0x20) {
          static const char* kHex = "0123456789abcdef";
          out->append("\\u00");
          out->push_back(kHex[(ch >> 4) & 0x0F]);
          out->push_back(kHex[ch & 0x0F]);
        } else {
          out->push_back(static_cast<char>(ch));
        }
        break;
    }
  }
  out->push_back('"');
}

void SerializeJsonValue(const JsonValue& value, int indent, std::string* out) {
  if (value.is_null()) {
    out->append("null");
    return;
  }
  if (value.is_bool()) {
    out->append(value.as_bool() ? "true" : "false");
    return;
  }
  if (value.is_int()) {
    out->append(std::to_string(value.as_int()));
    return;
  }
  if (value.is_string()) {
    AppendEscapedString(value.as_string(), out);
    return;
  }
  if (value.is_array()) {
    const JsonArray& array = value.as_array();
    if (array.empty()) {
      out->append("[]");
      return;
    }
    out->append("[\n");
    for (size_t i = 0; i < array.size(); ++i) {
      AppendIndent(indent + 2, out);
      SerializeJsonValue(array[i], indent + 2, out);
      if (i + 1 != array.size()) {
        out->push_back(',');
      }
      out->push_back('\n');
    }
    AppendIndent(indent, out);
    out->push_back(']');
    return;
  }

  const JsonObject& object = value.as_object();
  if (object.empty()) {
    out->append("{}");
    return;
  }
  out->append("{\n");
  size_t index = 0;
  for (const auto& item : object) {
    AppendIndent(indent + 2, out);
    AppendEscapedString(item.first, out);
    out->append(": ");
    SerializeJsonValue(item.second, indent + 2, out);
    if (++index != object.size()) {
      out->push_back(',');
    }
    out->push_back('\n');
  }
  AppendIndent(indent, out);
  out->push_back('}');
}

}  // namespace

bool operator==(const JsonValue& left, const JsonValue& right) {
  return left.value == right.value;
}

std::string ReadTextFile(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw SemanticBridgeError("unable to read file: " + path);
  }
  std::ostringstream out;
  out << file.rdbuf();
  return out.str();
}

JsonValue ParseJsonText(const std::string& text) {
  return JsonParser(text).Parse();
}

JsonValue ParseJsonFile(const std::string& path) {
  return ParseJsonText(ReadTextFile(path));
}

std::string SerializeJson(const JsonValue& value) {
  std::string out;
  SerializeJsonValue(value, 0, &out);
  out.push_back('\n');
  return out;
}

const JsonValue& RequireField(const JsonObject& object, const char* key) {
  const auto it = object.find(key);
  if (it == object.end()) {
    throw SemanticBridgeError(std::string("missing field: ") + key);
  }
  return it->second;
}

const JsonObject& RequireObject(const JsonValue& value, const char* what) {
  if (!value.is_object()) {
    throw SemanticBridgeError(std::string(what) + " must be an object");
  }
  return value.as_object();
}

const JsonArray& RequireArray(const JsonValue& value, const char* what) {
  if (!value.is_array()) {
    throw SemanticBridgeError(std::string(what) + " must be a list");
  }
  return value.as_array();
}

const std::string& RequireString(const JsonValue& value, const char* what) {
  if (!value.is_string()) {
    throw SemanticBridgeError(std::string("invalid ") + what);
  }
  return value.as_string();
}

int64_t RequireInt(const JsonValue& value, const char* what) {
  if (!value.is_int()) {
    throw SemanticBridgeError(std::string("invalid ") + what);
  }
  return value.as_int();
}

bool RequireBool(const JsonValue& value, const char* what) {
  if (!value.is_bool()) {
    throw SemanticBridgeError(std::string("invalid ") + what);
  }
  return value.as_bool();
}

}  // namespace sp_differ
