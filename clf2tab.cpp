#include <iostream>
#include <string>
#include <vector>
#include <time.h>
#include <sstream>

/*
 * This program parses Apache's Common Log Format
 * (http://httpd.apache.org/docs/1.3/logs.html#common)
 * and Combined Log Format into
 * IP, client-identity, user-id, unix-epoch-seconds, http-method, http-resource, http-protocol, status-code, returned-size[, referer[, user-agent]]
 * separated by tabs.
 *
 * It takes its input via stdin and writes to stdout.
 */

bool skip_validation;
#define IF_VALID(X) if(skip_validation || (X))
using std::vector;
using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::cin;
using std::stringstream;

/*
 * Parses calendar input into tm, converts to time_t, and reformats as a str.
 * logtime should be the format: day/month/year:hour:minute:second zone
 * day = 2*digit
 * month = 3*letter
 * year = 4*digit
 * hour = 2*digit
 * minute = 2*digit
 * second = 2*digit
 * zone = (`+' | `-') 4*digit
 *
 * e.g. 04/Apr/2012:10:37:29 -0500
 */
string logtimeToUnix(const string& logtime) {
  struct tm tm;
  time_t t;
  if (strptime(logtime.c_str(), "%d/%b/%Y:%H:%M:%S %Z", &tm) == NULL)
    return "-";

  tm.tm_isdst = 0; // Force dst off
  // Parse the timezone, the five digits start with the sign at idx 21.
  int hours = 10*(logtime[22] - '0') + logtime[23] - '0';
  int mins = 10*(logtime[24] - '0') + logtime[25] - '0';
  int off_secs = 60*60*hours + 60*mins;
  if (logtime[21] == '-')
    off_secs *= -1;

  t = mktime(&tm);
  if (t == -1)
    return "-";
  t -= timezone; // Local timezone
  t += off_secs;

  string retval;
  stringstream stream;
  stream << t;
  stream >> retval;
  return retval;
}

enum State {
  IP=0,
  CLIENT,
  USER,
  TIME,
  URL_METHOD,
  URL_PATH,
  URL_PROTOCOL,
  CODE,
  CONTENT,
  REFERER,
  AGENT
};

bool is_IP(const string& str) {
  // Verifies empty ('-'), containing only numbers or dots,
  // existence of 3 dots, and no more than 15 chars.
  const char* head = str.c_str();
  if (*head == '-')
    return true;
  short dots = 0;
  short len = 0;
  while (*head) {
    if (!(std::isdigit(*head) || *head == '.'))
      return false;
    if (*head == '.')
      ++dots;
    ++len;
    ++head;
  }
  return (dots == 3 && len <= 15);
}

bool is_numeric(const string& str) {
  const char* head = str.c_str();
  while (*head) {
    if (!std::isdigit(*head) && *head != '-')
      return false;
    ++head;
  }
  return true;
}

bool is_user(const string& str) {
  // Very liberal with what is allowed for a username.
  const char* head = str.c_str();
  if (!(std::isalpha(*head) || *head == '_' || (*head == '-' && !*(head+1))))
    return false;
  ++head;
  while (*head) {
    if (!(std::isalnum(*head) || *head == '_' || *head == '-' || *head == '@' || *head == '.'))
      return false;
    ++head;
  }
  return true;
}

void validate(State& state, const string& token) throw(const char*) {
  switch (state) {
    case IP:
      IF_VALID(is_IP(token)) {
        state = CLIENT;
      } else {
        throw "IP is invalid.";
      }
      break;
    case CLIENT:
      // RFC 1413 client identity, but should almost never be sent
      // so we don't support it.
      IF_VALID(token == "-") {
        state = USER;
      } else {
        throw "Client identity unsupported.";
      }
      break;
    case USER:
      IF_VALID(is_user(token)) {
        state = TIME;
      } else {
        throw "USER is invalid.";
      }
      break;
    case TIME:
      IF_VALID(is_numeric(token)) {
        state = URL_METHOD;
      } else {
        throw "TIME is not numeric.";
      }
      break;
    case URL_METHOD:
      // Potentially check for -standard- request methods:
      // PUT, POST, GET, DELETE, PATCH. However they can
      // potentially be anything, so we just punt.
      state = URL_PATH;
      break;
    case URL_PATH:
      IF_VALID(token[0] == '/') {
        state = URL_PROTOCOL;
      } else {
        throw "PATH does not begin with forward slash.";
      }
      break;
    case URL_PROTOCOL:
      // Protocol also changes depending on application, so
      // we also punt here.
      state = CODE;
      break;
    case CODE:
      IF_VALID(is_numeric(token)) {
        state = CONTENT;
      } else {
        throw "CODE is not numeric.";
      }
      break;
    case CONTENT:
      IF_VALID(is_numeric(token)) {
        state = REFERER;
      } else {
        throw "CONTENT is not numeric.";
      }
      break;
    // Both Ref and Agent can be any arbitrary string.
    case REFERER:
      state = AGENT;
      break;
    case AGENT:
      break;
  }
}

/*
 * Simple FSM, progresses through each section of the CLF.
 * This is the state transition order (same as the enum):
 * State 1: IP (may have more non-standard addresses, separated by commas)
 * State 2: Client identity
 * State 3: User
 * State 4: Time
 * State 5: URL pieces (method, path, protocol)
 * State 6: Status Code
 * State 7: Returned content size
 * State 8 (optional): Referer [sic]
 * State 9 (optional): User-agent.
 * 
 * When a state has completed, the input goes through a CLF validator which
 * will continue to the next state if valid or else send the line to stderr.
 */
void scanCLF(const string& line) throw(const char*) {
  vector<string> tokens;
  tokens.reserve(16);
  string token("");
  State state = IP;
  for (string::const_iterator it = line.begin(); it != line.end(); ++it) {
    switch(state) {
      case IP:
      case CLIENT:
      case USER:
      case CODE:
      case CONTENT:
        if (*it != ' ' && *it != ',') {
          token += *it;
        } else if (*it == ',' && state == IP) { // Support for more IPs
          tokens.push_back(token);
          token.clear();
        } else if (!token.empty()) {
          validate(state, token);
          tokens.push_back(token);
          token.clear();
        }
        // Optional case 8 not reached:
        if (it+1 == line.end() && !token.empty()) {
          tokens.push_back(token);
        }
        break;
      case TIME:
        if (*it != '[' && *it != ']') {
          token += *it;
        } else if (*it == ']') {
          string converted = logtimeToUnix(token);
          validate(state, converted);
          tokens.push_back(converted);
          token.clear();
        }
        break;
      case URL_METHOD:
      case URL_PATH:
      case URL_PROTOCOL:
        if (*it != '"' || *(it-1) == '\\') {
          if (*it != ' ') {
            token += *it;
          } else if (!token.empty()) {
            validate(state, token);
            tokens.push_back(token);
            token.clear();
          }
        } else if (!token.empty()) {
          validate(state, token);
          tokens.push_back(token);
          token.clear();
        }
        break;
      case REFERER:
      case AGENT:
        if ((*it != '"' || *(it-1) == '\\') && (*it != ' ' || !token.empty())) {
          token += *it;
        } else if (!token.empty()) {
          validate(state, token);
          tokens.push_back(token);
          token.clear();
        }
        break;
    }
  }

  for (unsigned i = 0; i < tokens.size(); ++i) {
    cout << tokens[i];
    if (i+1 < tokens.size())
     cout << "\t";
  }
  cout << endl;
}

int main() {
  skip_validation = false; // Produced no noticeable difference in speed
  // while processing 25k records.
  string line;
  // This often makes input much faster but creates
  // a memory leak because standard streams are *never*
  // destroyed as per the standard.
  cin.sync_with_stdio(false);
  while (std::getline(cin, line)) {
    try {
      scanCLF(line);
    } catch (const char* e) {
      cerr << "Error \"" << e << "\" on line: " << line << endl;
    }
  }
  return 0;
}
