<?php
@ini_set('output_buffering','0');
@ini_set('zlib.output_compression','0');
while (ob_get_level()) ob_end_clean();
for ($i = 1; $i <= 5; $i++) {
    echo "tick $i\n";
    flush();
    usleep(500000); // 0.5 Гл
}
