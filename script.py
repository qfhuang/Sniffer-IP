import sys
import struct

psd = struct.Struct("< B I Q B")

first_timestamp_us = 0
last_timestamp_us = 0

with open(sys.argv[1], "rb") as fp:

   while True:

      data = fp.read(271)

      if len(data) == 271:

         (packet_info, packet_number, raw_timestamp, packet_length) = psd.unpack(data[0:14])
         packet = data[14:(14 + packet_length)]

         time_lo = raw_timestamp & 0xFFFF
         time_hi = raw_timestamp >> 16
         timestamp = (time_hi * 5000 + time_lo) >> 5

         if 0 == first_timestamp_us:
            first_timestamp_us = timestamp
            timestamp = 0
         else:
            timestamp = timestamp - first_timestamp_us

         print("%2x %6u %12dus (+%8.3fms) [%3u]" % (packet_info, packet_number, timestamp, (timestamp - last_timestamp_us) / 1000.0, packet_length))
         last_timestamp_us = timestamp

      else:
         if len(data):
            print("Short read: %d" % (len(data)))
         break