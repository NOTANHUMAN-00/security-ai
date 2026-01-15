// Package challenges - Honeypot implementation
// The "Trap" module that injects invisible form fields to catch bots
package challenges

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"sentinel-x/internal/config"
)

// Honeypot manages the injection of invisible form fields
type Honeypot struct {
	config      *config.Config
	formPattern *regexp.Regexp
}

// NewHoneypot creates a new Honeypot instance
func NewHoneypot(cfg *config.Config) *Honeypot {
	return &Honeypot{
		config:      cfg,
		formPattern: regexp.MustCompile(`(?i)(<form[^>]*>)`),
	}
}

// InjectFields injects honeypot fields into HTML forms
func (h *Honeypot) InjectFields(body []byte) []byte {
	// Find all forms and inject honeypot fields after the opening tag
	return h.formPattern.ReplaceAllFunc(body, func(match []byte) []byte {
		honeypotHTML := h.generateHoneypotFields()
		return append(match, []byte(honeypotHTML)...)
	})
}

// generateHoneypotFields creates the invisible honeypot input fields
func (h *Honeypot) generateHoneypotFields() string {
	var builder strings.Builder
	
	builder.WriteString("\n<!-- Sentinel-X Security Fields - Do not modify -->\n")
	
	for _, fieldName := range h.config.Honeypot.FieldNames {
		// Use multiple hiding techniques for robustness
		// Bots that try to fill all fields will trigger the trap
		builder.WriteString(fmt.Sprintf(
			`<div style="position:absolute;left:-9999px;top:-9999px;opacity:0;height:0;width:0;overflow:hidden;" aria-hidden="true">
    <input type="text" name="%s" id="sx_%s" value="" tabindex="-1" autocomplete="off">
</div>`,
			fieldName, fieldName))
	}
	
	builder.WriteString("\n<!-- End Sentinel-X Security Fields -->\n")
	
	return builder.String()
}

// CheckRequest validates that honeypot fields are empty in a request
// Returns true if a bot was detected (honeypot triggered)
func (h *Honeypot) CheckRequest(formValues map[string][]string) bool {
	for _, fieldName := range h.config.Honeypot.FieldNames {
		if values, exists := formValues[fieldName]; exists {
			for _, value := range values {
				if value != "" {
					return true // Bot detected!
				}
			}
		}
	}
	return false
}

// GenerateClientScript returns JavaScript code for the client
// This helps prevent simple form-filling bots
func (h *Honeypot) GenerateClientScript() string {
	return `
<script>
(function() {
    // Sentinel-X Honeypot Protection
    // Ensures honeypot fields remain hidden for legitimate users
    document.addEventListener('DOMContentLoaded', function() {
        var honeypots = document.querySelectorAll('[id^="sx_"]');
        honeypots.forEach(function(field) {
            field.value = '';
            field.setAttribute('readonly', 'readonly');
        });
    });
})();
</script>`
}

// AdvancedHoneypot provides more sophisticated bot detection
type AdvancedHoneypot struct {
	*Honeypot
}

// NewAdvancedHoneypot creates an advanced honeypot with additional detection
func NewAdvancedHoneypot(cfg *config.Config) *AdvancedHoneypot {
	return &AdvancedHoneypot{
		Honeypot: NewHoneypot(cfg),
	}
}

// InjectAdvancedFields injects fields with JavaScript timing detection
func (h *AdvancedHoneypot) InjectAdvancedFields(body []byte) []byte {
	// First inject basic honeypot fields
	body = h.InjectFields(body)
	
	// Then inject timing script before </body>
	timingScript := []byte(h.generateTimingScript())
	
	// Find </body> tag and inject before it
	bodyClose := bytes.Index(bytes.ToLower(body), []byte("</body>"))
	if bodyClose != -1 {
		newBody := make([]byte, 0, len(body)+len(timingScript))
		newBody = append(newBody, body[:bodyClose]...)
		newBody = append(newBody, timingScript...)
		newBody = append(newBody, body[bodyClose:]...)
		return newBody
	}
	
	return body
}

// generateTimingScript creates script that tracks form interaction timing
func (h *AdvancedHoneypot) generateTimingScript() string {
	return `
<script>
(function() {
    // Sentinel-X Form Timing Protection
    var formLoadTime = Date.now();
    var interactionCount = 0;
    
    document.addEventListener('keydown', function() { interactionCount++; });
    document.addEventListener('click', function() { interactionCount++; });
    document.addEventListener('mousemove', function() { interactionCount++; }, {once: true});
    
    // Attach to all forms
    document.querySelectorAll('form').forEach(function(form) {
        form.addEventListener('submit', function(e) {
            var submissionTime = Date.now() - formLoadTime;
            
            // Create hidden timing field
            var timingField = document.createElement('input');
            timingField.type = 'hidden';
            timingField.name = '_sx_timing';
            timingField.value = submissionTime + ':' + interactionCount;
            form.appendChild(timingField);
            
            // If form was filled too fast (under 2 seconds) with no interaction
            // This is likely a bot, but we don't block - just flag for server-side analysis
            if (submissionTime < 2000 && interactionCount < 3) {
                var flagField = document.createElement('input');
                flagField.type = 'hidden';
                flagField.name = '_sx_flag';
                flagField.value = 'fast_submit';
                form.appendChild(flagField);
            }
        });
    });
})();
</script>`
}
