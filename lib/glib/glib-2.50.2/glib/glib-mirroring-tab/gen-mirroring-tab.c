/* gen-mirroring-tab.c - generate gmirroringtable.h for glib
 * copied from FriBidi.
 *
 * $Id$
 * $Author$
 * $Date$
 * $Revision$
 * $Source$
 *
 * Author:
 *   Behdad Esfahbod, 2001, 2002, 2004
 *
 * Copyright (C) 2004 Sharif FarsiWeb, Inc
 * Copyright (C) 2001,2002,2004 Behdad Esfahbod
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library, in a file named COPYING; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA
 * 
 * For licensing issues, contact <license@farsiweb.info>.
 */

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>

#include "packtab.h"

#define appname "gen-mirroring-tab"
#define outputname "gmirroringtable.h"

static void
die (
  const char *msg
)
{
  fprintf (stderr, appname ": %s\n", msg);
  exit (1);
}

static void
die2 (
  const char *fmt,
  const char *p
)
{
  fprintf (stderr, appname ": ");
  fprintf (stderr, fmt, p);
  fprintf (stderr, "\n");
  exit (1);
}

static void
die4 (
  const char *fmt,
  unsigned long l,
  unsigned long p,
  unsigned long q
)
{
  fprintf (stderr, appname ": ");
  fprintf (stderr, fmt, l, p, q);
  fprintf (stderr, "\n");
  exit (1);
}

#define table_name "Mir"
#define macro_name "GLIB_GET_MIRRORING"

#define UNICODE_CHARS 0x110000

static signed int table[UNICODE_CHARS];
static char buf[4000];
static signed long max_dist;

static void
init (
  void
)
{
  max_dist = 0;
}

static void
clear_tab (
  void
)
{
  register gunichar c;

  for (c = 0; c < UNICODE_CHARS; c++)
    table[c] = 0;
}

static void
init_tab_mirroring_txt (
  void
)
{
  clear_tab ();
}

static void
read_bidi_mirroring_txt (
  FILE *f
)
{
  unsigned long l;

  init_tab_mirroring_txt ();

  l = 0;
  while (fgets (buf, sizeof buf, f))
    {
      unsigned long i, j;
      signed long dist;
      int k;
      const char *s = buf;

      l++;

      while (*s == ' ')
	s++;

      if (s[0] == '#' || s[0] == '\0' || s[0] == '\n')
	continue;

      k = sscanf (s, "%lx; %lx", &i, &j);
      if (k != 2 || i >= UNICODE_CHARS || j >= UNICODE_CHARS)
	die4 ("invalid pair in input at line %lu: %04lX, %04lX", l, i, j);
      dist = ((signed long) j - (signed long) i);
      table[i] = dist;
      if (dist > max_dist)
	max_dist = dist;
      else if (-dist > max_dist)
	max_dist = -dist;
    }
}

static void
read_data (
  const char *data_file_type,
  const char *data_file_name
)
{
  FILE *f;

  fprintf (stderr, "Reading '%s'\n", data_file_name);
  if (!(f = fopen (data_file_name, "rt")))
    die2 ("error: cannot open '%s' for reading", data_file_name);

  if (!strcmp (data_file_type, "BidiMirroring.txt"))
    read_bidi_mirroring_txt (f);
  else
    die2 ("error: unknown data-file-type %s", data_file_type);

  fclose (f);
}

static void
gen_mirroring_tab (
  int max_depth,
  const char *data_file_type
)
{
  int key_bytes;
  const char *key_type;

  fprintf (stderr,
	   "Generating '" outputname "', it may take up to a few minutes\n");
  printf ("/* " outputname "\n * generated by " appname " "
	  "\n" " * from the file %s of */\n\n", data_file_type);

  printf ("#define PACKTAB_UINT8 guint8\n"
	  "#define PACKTAB_UINT16 guint16\n"
	  "#define PACKTAB_UINT32 guint32\n\n");

  key_bytes = max_dist <= 0x7f ? 1 : max_dist < 0x7fff ? 2 : 4;
  key_type = key_bytes == 1 ? "gint8" : key_bytes == 2 ?
    "gint16" : "gint32";

  if (!pack_table
      (table, UNICODE_CHARS, key_bytes, 0, max_depth, 1, NULL,
       key_type, table_name, macro_name "_DELTA", stdout))
    die ("error: insufficient memory, decrease max_depth");

  printf ("#undef PACKTAB_UINT8\n"
	  "#undef PACKTAB_UINT16\n" "#undef PACKTAB_UINT32\n\n");

  printf ("#define " macro_name "(x) ((x) + " macro_name "_DELTA(x))\n\n");

  printf ("/* End of generated " outputname " */\n");
}

int
main (
  int argc,
  const char **argv
)
{
  const char *data_file_type = "BidiMirroring.txt";

  if (argc < 3)
    die2 ("usage:\n  " appname " max-lookups /path/to/%s [junk...]",
	  data_file_type);

  {
    int max_depth = atoi (argv[1]);
    const char *data_file_name = argv[2];

    if (max_depth < 2)
      die ("invalid depth");

    init ();
    read_data (data_file_type, data_file_name);
    gen_mirroring_tab (max_depth, data_file_type);
  }

  return 0;
}
