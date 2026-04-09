#ifndef SP_DIFFER_RUNNER_SEMANTIC_JSON_HPP
#define SP_DIFFER_RUNNER_SEMANTIC_JSON_HPP

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace sp_differ {

class SemanticBridgeError : public std::runtime_error {
 public:
  explicit SemanticBridgeError(const std::string& message) : std::runtime_error(message) {}
};

struct JsonValue;
using JsonObject = std::map<std::string, JsonValue>;
using JsonArray = std::vector<JsonValue>;

struct JsonValue {
  using Variant =
      std::variant<std::nullptr_t, bool, int64_t, std::string, JsonArray, JsonObject>;

  Variant value;

  JsonValue() : value(nullptr) {}
  JsonValue(std::nullptr_t) : value(nullptr) {}
  JsonValue(bool input) : value(input) {}
  JsonValue(int input) : value(static_cast<int64_t>(input)) {}
  JsonValue(uint32_t input) : value(static_cast<int64_t>(input)) {}
  JsonValue(uint64_t input) : value(static_cast<int64_t>(input)) {}
  JsonValue(int64_t input) : value(input) {}
  JsonValue(const char* input) : value(std::string(input)) {}
  JsonValue(std::string input) : value(std::move(input)) {}
  JsonValue(JsonArray input) : value(std::move(input)) {}
  JsonValue(JsonObject input) : value(std::move(input)) {}

  bool is_null() const { return std::holds_alternative<std::nullptr_t>(value); }
  bool is_bool() const { return std::holds_alternative<bool>(value); }
  bool is_int() const { return std::holds_alternative<int64_t>(value); }
  bool is_string() const { return std::holds_alternative<std::string>(value); }
  bool is_array() const { return std::holds_alternative<JsonArray>(value); }
  bool is_object() const { return std::holds_alternative<JsonObject>(value); }

  const bool& as_bool() const { return std::get<bool>(value); }
  bool& as_bool() { return std::get<bool>(value); }

  const int64_t& as_int() const { return std::get<int64_t>(value); }
  int64_t& as_int() { return std::get<int64_t>(value); }

  const std::string& as_string() const { return std::get<std::string>(value); }
  std::string& as_string() { return std::get<std::string>(value); }

  const JsonArray& as_array() const { return std::get<JsonArray>(value); }
  JsonArray& as_array() { return std::get<JsonArray>(value); }

  const JsonObject& as_object() const { return std::get<JsonObject>(value); }
  JsonObject& as_object() { return std::get<JsonObject>(value); }
};

bool operator==(const JsonValue& left, const JsonValue& right);

std::string ReadTextFile(const std::string& path);
JsonValue ParseJsonText(const std::string& text);
JsonValue ParseJsonFile(const std::string& path);
std::string SerializeJson(const JsonValue& value);

const JsonValue& RequireField(const JsonObject& object, const char* key);
const JsonObject& RequireObject(const JsonValue& value, const char* what);
const JsonArray& RequireArray(const JsonValue& value, const char* what);
const std::string& RequireString(const JsonValue& value, const char* what);
int64_t RequireInt(const JsonValue& value, const char* what);
bool RequireBool(const JsonValue& value, const char* what);

}  // namespace sp_differ

#endif  // SP_DIFFER_RUNNER_SEMANTIC_JSON_HPP
