import csv
import sys
import os
from pathlib import Path

def aggregate_csv_files(output_file, input_files):

    if not input_files:
        print ("error, no input files entered")
        return False
    
    missing_files = []
    for file in input_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f" missing files: {missing_files}")
        return False

    print(f"Aggregating {len(input_files)} files to {output_file}")

    total_rows = 0
    first_file = True

    with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        writer = None

        for i, input_file in enumerate(input_files):
            print(f"writing {input_file}")

            with open(input_file, 'r', newline='', encoding='utf-8') as infile:
                reader = csv.reader(infile)

                if first_file:
                    header = next(reader, None)
                    if header:
                        writer = csv.writer(outfile)
                        writer.writerow(header)
                        print(f"Header wrote: {header}")
                    first_file = False
                else:
                    next(reader, None)
                
                file_rows = 0
                for row in reader:
                    if row:
                        writer.writerow(row)
                        file_rows += 1
                        total_rows += 1
                print(f"{file_rows} rows wrote")

    print(f"Aggregation terminated")
    print(f"{total_rows} wrote in total")

    return True

def main():

    output_file = sys.argv[1]
    input_files = sys.argv[2:]

    if os.path.exists(output_file):
        response = input(f"⚠️  The file {output_file} already exist. Overwrite? (y/N): ")
        if response.lower() not in ['y', 'yes', 'oui', '']:
            print(" Operation aborted")
            sys.exit(1)

    success = aggregate_csv_files(output_file, input_files)

    if success:
        print("\n✅ Agregation succeded")
        
        with open(output_file, 'r') as f:
            total_lines = sum(1 for line in f)
        
        file_size = os.path.getsize(output_file)
        print(f"final stats:")
        print(f"   - total rows: {total_lines}")
        print(f"   - size: {file_size / 1024:.1f} KB")
    else:
        print("\nAgregation failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
