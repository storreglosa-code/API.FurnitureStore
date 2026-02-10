using System.Collections.Generic;
using System.Threading.Tasks;
using API.FurnitoreStore.Application.Dtos.Product;

namespace API.FurnitoreStore.Application.Interfaces
{
    public interface IProductsService
    {
        Task<IEnumerable<ReadProductDto>> GetAllAsync();
        Task<ReadProductDto?> GetByIdAsync(int id);
        Task<ReadProductDto> CreateAsync(CreateProductDto product);
        Task UpdateAsync(UpdateProductDto product);
        Task DeleteAsync(int id);
    }
}