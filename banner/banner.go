package banner

import (
	"fmt"
)

// prints the version message
const version = "v0.0.4"

func PrintVersion() {
	fmt.Printf("Current ipfinder version %s\n", version)
}

// Prints the Colorful banner
func PrintBanner() {
	banner := `
                           _  __               __                            __   _             
  ___   ____ ___   ____ _ (_)/ /____ _ __  __ / /_ ____   ____ ___   ____ _ / /_ (_)____   ____ 
 / _ \ / __  __ \ / __  // // // __  // / / // __// __ \ / __  __ \ / __  // __// // __ \ / __ \
/  __// / / / / // /_/ // // // /_/ // /_/ // /_ / /_/ // / / / / // /_/ // /_ / // /_/ // / / /
\___//_/ /_/ /_/ \__,_//_//_/ \__,_/ \__,_/ \__/ \____//_/ /_/ /_/ \__,_/ \__//_/ \____//_/ /_/
`
	fmt.Printf("%s\n%75s\n\n", banner, "Current ipfinder version "+version)
}
