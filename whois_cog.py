import discord
from redbot.core import commands
import subprocess
import shlex
import time  # Added for timing the execution

class WhoisCog(commands.Cog):
    """A cog to query WHOIS information and display it in Discord."""

    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def whois(self, ctx, ip: str):
        """Query WHOIS information for a given IP."""
        try:
            # Start the timer
            start_time = time.perf_counter()

            # Sanitize the IP input to prevent command injection
            sanitized_ip = shlex.quote(ip)

            # Run the whois command on the server with a timeout of 10 seconds
            result = subprocess.run(["whois", sanitized_ip], capture_output=True, text=True, timeout=10)

            # Check if the whois command execution was successful
            if result.returncode != 0:
                # If not, retrieve and send the error message
                error_message = result.stderr.strip() if result.stderr else "Unknown error."
                await ctx.send(f"Failed to query WHOIS information: {error_message}")
                return

            # Parse the WHOIS output
            whois_data = result.stdout

            # Detect the registry using a dictionary mapping (case-insensitive lookup)
            registries = {
                "ripe": "ripe",
                "apnic": "apnic",
                "afrinic": "afrinic",
                "lacnic": "lacnic",
                "arin": "arin"
            }

            # Match the registry from the WHOIS data
            registry = next((value for key, value in registries.items() if key.lower() in whois_data.lower()), None)

            # Extract fields based on the detected registry
            if registry == "ripe":
                netname = self._extract_field(whois_data, "netname", registry)
                descr = self._extract_multiline_field(whois_data, "descr", registry)
                country = self._extract_field(whois_data, "country", registry)
                address = self._extract_multiline_field(whois_data, "address", registry)
                organisation = self._extract_field(whois_data, "organisation", registry)
                as_number = self._extract_field(whois_data, "origin", registry)
            elif registry == "apnic":
                netname = self._extract_field(whois_data, "NetName", registry)
                descr = self._extract_multiline_field(whois_data, "desc", registry)
                country = self._extract_field(whois_data, "Country", registry)
                address = self._extract_multiline_field(whois_data, "Address", registry)
                organisation = self._extract_field(whois_data, "Organisation", registry)
                as_number = self._extract_field(whois_data, "origin", registry)
            elif registry == "afrinic":
                netname = self._extract_field(whois_data, "NetName", registry)
                descr = self._extract_multiline_field(whois_data, "Descr", registry)
                country = self._extract_field(whois_data, "Country", registry)
                address = self._extract_multiline_field(whois_data, "Address", registry)
                organisation = self._extract_field(whois_data, "Organisation", registry)
                as_number = self._extract_field(whois_data, "origin", registry)
            elif registry == "lacnic":
                netname = self._extract_field(whois_data, "NetName", registry)
                descr = self._extract_multiline_field(whois_data, "responsible", registry)
                country = self._extract_field(whois_data, "country", registry)
                address = self._extract_multiline_field(whois_data, "address", registry)
                organisation = self._extract_field(whois_data, "owner", registry)
                as_number = self._extract_field(whois_data, "aut-num", registry)
            elif registry == "arin":
                netname = self._extract_field(whois_data, "NetName")
                descr = self._extract_multiline_field(whois_data, "Comment")
                country = self._extract_field(whois_data, "Country")
                # Combine address components for ARIN, excluding country
                city = self._extract_field(whois_data, "City")
                state = self._extract_field(whois_data, "State/Province")
                address = self._extract_multiline_field(whois_data, "Address")
                address_parts = [address, city, state]
                address = "\n".join(part for part in address_parts if part and part.lower() != "none")
                organisation = self._extract_field(whois_data, "organization")
                as_number = self._extract_field(whois_data, "origin")
            else:
                # Default extraction for unknown registries
                netname = self._extract_field(whois_data, "NetName")
                descr = self._extract_multiline_field(whois_data, "Comment")
                country = self._extract_field(whois_data, "Country")
                address = self._extract_multiline_field(whois_data, "Address")
                organisation = self._extract_field(whois_data, "Organisation")
                as_number = self._extract_field(whois_data, "origin")

            # Calculate elapsed time
            elapsed_time = time.perf_counter() - start_time

            # Create the embed message with the parsed WHOIS data
            embed = discord.Embed(
                title=f"WHOIS Information for {ip}",
                color=discord.Color.blue()
            )
            embed.add_field(name="NetName", value=netname or "N/A", inline=False)
            embed.add_field(name="Organisation", value=organisation or "N/A", inline=False)
            embed.add_field(name="Description", value=descr or "N/A", inline=False)
            embed.add_field(name="Country", value=country or "N/A", inline=False)
            embed.add_field(name="Address", value=address or "N/A", inline=False)
            embed.add_field(name="AS Number", value=as_number or "N/A", inline=False)
            embed.add_field(name="Registry", value=registry.upper() if registry else "Unknown", inline=False)
            embed.set_footer(text=f"Query completed in {elapsed_time * 1000:.2f}ms")

            # Send the embed message to the Discord channel
            await ctx.send(embed=embed)

        except subprocess.TimeoutExpired:
            # Handle timeout errors if the whois command takes too long
            await ctx.send("The WHOIS query took too long to respond. Please try again later.")
        except Exception as e:
            # Catch and report any unexpected errors
            await ctx.send(f"An error occurred: {e}")

    def _extract_field(self, data, field, registry=None):
        """Extract a specific field from the WHOIS data."""
        for line in data.splitlines():
            # Match lines starting with the field name (case-insensitive)
            if line.strip().lower().startswith(field.lower()):
                parts = line.split(":", 1)
                # Return the value part after the colon
                if len(parts) > 1:
                    return parts[1].strip()
        return None

    def _extract_multiline_field(self, data, field, registry=None):
        """Extract a multiline field from the WHOIS data."""
        lines = []
        capture = False
        for line in data.splitlines():
            # Start capturing if the line starts with the field name
            if line.strip().lower().startswith(field.lower()):
                capture = True
                parts = line.split(":", 1)
                # Add the first value part if present
                if len(parts) > 1:
                    lines.append(parts[1].strip())
            elif capture:
                # Continue capturing indented lines as part of the field
                if line.startswith(" ") or line.startswith("\t"):
                    lines.append(line.strip())
                else:
                    # Stop capturing when a non-indented line is encountered
                    break
        # Join captured lines into a single string
        return "\n".join(lines) if lines else None

# Setup function for Redbot
from redbot.core.bot import Red

async def setup(bot: Red):
    cog = WhoisCog(bot)
    await bot.add_cog(cog)
