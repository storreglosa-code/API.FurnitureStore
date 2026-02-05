using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using API.FornitureStore.Data;
using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Application.Dtos;
using API.FurnitoreStore.Share;

namespace API.FurnitoreStore.Application.Services
{
    public class ProductsService : IProductsService
    {
        private readonly ApplicationDbContext _context;

        public ProductsService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<ReadProductDto> CreateAsync(CreateProductDto dto)
        {
            try
            {
                var entity = new Product
                {
                    Name = dto.Name,
                    Price = dto.Price,
                    ProductCategoryId = dto.ProductCategoryId
                };

                await _context.Products.AddAsync(entity);
                await _context.SaveChangesAsync();

                return MapToReadDto(entity);
            }
            catch (Exception ex)
            {
                throw new Exception("Error creating product", ex);
            }
        }

        public async Task DeleteAsync(int id)
        {
            try
            {
                var existing = await _context.Products.FindAsync(id);
                if (existing == null)
                    throw new Exception("Product not found.");

                _context.Products.Remove(existing);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                throw new Exception("Error deleting product", ex);
            }
        }

        public async Task<IEnumerable<ReadProductDto>> GetAllAsync()
        {
            try
            {
                var products = await _context.Products
                                             .AsNoTracking()
                                             .ToListAsync();
                return products.Select(MapToReadDto);
            }
            catch (Exception ex)
            {
                throw new Exception("Error retrieving products", ex);
            }
        }

        public async Task<ReadProductDto?> GetByIdAsync(int id)
        {
            try
            {
                var product = await _context.Products
                                            .AsNoTracking()
                                            .FirstOrDefaultAsync(p => p.Id == id);
                if (product == null) return null;
                return MapToReadDto(product);
            }
            catch (Exception ex)
            {
                throw new Exception("Error retrieving product", ex);
            }
        }

        public async Task UpdateAsync(UpdateProductDto dto)
        {
            try
            {
                var existing = await _context.Products.FindAsync(dto.Id);
                if (existing == null)
                    throw new Exception("Product not found.");

                existing.Name = dto.Name;
                existing.Price = dto.Price;
                existing.ProductCategoryId = dto.ProductCategoryId;

                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                throw new Exception("Error updating product", ex);
            }
        }

        // Manual mapping helpers
        private static ReadProductDto MapToReadDto(Product p) =>
            new ReadProductDto
            {
                Id = p.Id,
                Name = p.Name ?? string.Empty,
                Price = p.Price,
                ProductCategoryId = p.ProductCategoryId
            };
    }
}